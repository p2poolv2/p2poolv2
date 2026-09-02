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

use crate::shares::share_block::ShareTransaction;
use crate::shares::witness_commitment::{WITNESS_COMMITMENT_LENGTH, WitnessCommitment};
use bitcoin::consensus::Encodable;
use bitcoin::hashes::{Hash, HashEngine, sha256d};
use bitcoin::script::Builder;
use bitcoin::{
    BlockHash, ScriptBuf, Transaction, TxMerkleNode, TxOut, WitnessMerkleNode, WitnessProgram,
    Wtxid, merkle_tree,
};

const SHARE_VALUE: u64 = 1; // 100_000_000 satoshi == 1 BTC == 1 share
/// BIP141 witness commitment header: OP_RETURN, push 36, magic "aa21a9ed".
const BIP141_COMMITMENT_HEADER: [u8; 6] = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
/// Witness reserved value (BIP141): 32 zero bytes, stored as the sole
/// witness stack item of the coinbase input.
const WITNESS_RESERVED_VALUE: [u8; 32] = [0u8; 32];

/// Create a coinbase transaction for the given share chain miner address.
///
/// Builds a coinbase that pays the miner one share unit and embeds a
/// BIP141 witness commitment covering the provided share transactions.
/// The caller must pass every non-coinbase transaction that will be
/// included in the share block (in order); the coinbase's own wtxid is
/// replaced by all-zeros when computing the witness root, per BIP141.
///
/// Also places the 32-byte witness reserved value on the coinbase input's
/// witness stack so validators can recompute the commitment.
///
/// `weak_block_hash` is what makes this transaction unique per share, and it
/// is the only thing that does. Every other input is the same for every share
/// a miner produces for a given work notify.
///
/// Taking it here is only sound because the share commitment does *not* cover
/// this transaction. It covers the non-coinbase transactions instead, via
/// [`compute_non_coinbase_root`]. Putting the merkle root of the whole set
/// back into the commitment would make this circular: the hash would depend on
/// a coinbase that depends on the hash.
pub fn build_sharechain_coinbase_transaction(
    miner_address: &WitnessProgram,
    weak_block_hash: BlockHash,
    other_share_transactions: &[ShareTransaction],
) -> Transaction {
    let script_pubkey = ScriptBuf::new_witness_program(miner_address);

    let payout_output = TxOut {
        value: bitcoin::Amount::from_int_btc(SHARE_VALUE),
        script_pubkey,
    };

    let witness_commitment_output = build_witness_commitment_output(other_share_transactions);

    let mut witness = bitcoin::Witness::new();
    witness.push(WITNESS_RESERVED_VALUE);

    let tx_in = bitcoin::TxIn {
        previous_output: bitcoin::OutPoint::null(),
        script_sig: Builder::new()
            .push_slice(weak_block_hash.to_byte_array())
            .into_script(),
        sequence: bitcoin::Sequence::MAX,
        witness,
    };

    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![tx_in],
        output: vec![payout_output, witness_commitment_output],
    }
}

/// Merkle root over a share's non-coinbase transactions, for the commitment.
///
/// The commitment is fixed at notify time, before the miner hashes, so it can
/// only cover what is known then. The coinbase is not: it carries the weak
/// block hash, which exists only once the work is done. So the commitment
/// covers these transactions and the coinbase is bound separately, by
/// reconstruction during validation.
///
/// Returns all zeros for an empty list. That is a convention, not a derived
/// value: `merkle_tree::calculate_root` returns `None` here because the merkle
/// root of an empty tree is undefined. All zeros matches what
/// [`compute_witness_root`] falls back to, and no real root can collide with
/// it short of a preimage.
///
/// The empty case is the only one that arises today, since share blocks carry
/// nothing but their coinbase. Both the notify path and validation must call
/// this one function: the value is hashed into the commitment, so two
/// implementations that disagree would produce shares no peer accepts.
pub fn compute_non_coinbase_root(other_share_transactions: &[ShareTransaction]) -> TxMerkleNode {
    let txids = other_share_transactions
        .iter()
        .map(|transaction| transaction.compute_txid().to_raw_hash());
    merkle_tree::calculate_root(txids)
        .map(TxMerkleNode::from_raw_hash)
        .unwrap_or_else(|| TxMerkleNode::from_raw_hash(Hash::all_zeros()))
}

/// Build the BIP141 witness commitment output for a share coinbase.
///
/// The witness root is computed from wtxids of `other_share_transactions`,
/// prepended with an all-zero wtxid standing in for the coinbase itself.
fn build_witness_commitment_output(other_share_transactions: &[ShareTransaction]) -> TxOut {
    let witness_root = compute_witness_root(other_share_transactions);
    let commitment_hash = compute_commitment_hash(&witness_root, &WITNESS_RESERVED_VALUE);

    let mut script_bytes = [0u8; WITNESS_COMMITMENT_LENGTH];
    script_bytes[..6].copy_from_slice(&BIP141_COMMITMENT_HEADER);
    script_bytes[6..].copy_from_slice(commitment_hash.as_byte_array());
    let commitment = WitnessCommitment::new(script_bytes);

    TxOut {
        value: bitcoin::Amount::ZERO,
        script_pubkey: commitment.to_script_buf(),
    }
}

/// Compute the BIP141 witness merkle root for a share block. The coinbase
/// wtxid is replaced with all-zeros.
pub(crate) fn compute_witness_root(
    other_share_transactions: &[ShareTransaction],
) -> WitnessMerkleNode {
    let all_zeros = Wtxid::all_zeros().to_raw_hash();
    let hashes = std::iter::once(all_zeros).chain(
        other_share_transactions
            .iter()
            .map(|share_transaction| share_transaction.compute_wtxid().to_raw_hash()),
    );
    merkle_tree::calculate_root(hashes)
        .map(WitnessMerkleNode::from_raw_hash)
        .unwrap_or_else(|| WitnessMerkleNode::from_raw_hash(all_zeros))
}

/// Compute the BIP141 commitment hash: SHA256d(witness_root || reserved_value).
pub(crate) fn compute_commitment_hash(
    witness_root: &WitnessMerkleNode,
    witness_reserved_value: &[u8],
) -> sha256d::Hash {
    let mut engine = sha256d::Hash::engine();
    witness_root
        .consensus_encode(&mut engine)
        .expect("hash engine never fails");
    engine.input(witness_reserved_value);
    sha256d::Hash::from_engine(engine)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stand-in weak block hash. Real shares take this from their bitcoin
    /// header; these tests only need it to be fixed so txids are stable.
    pub(super) fn test_weak_block_hash() -> BlockHash {
        BlockHash::from_byte_array([0x11; 32])
    }

    use crate::test_utils::make_test_share_program;

    #[test]
    fn test_create_share_block_coinbase_transaction() {
        let address = make_test_share_program(1);

        let transaction =
            build_sharechain_coinbase_transaction(&address, test_weak_block_hash(), &[]);

        assert_eq!(transaction.version, bitcoin::transaction::Version::TWO);
        assert_eq!(transaction.lock_time, bitcoin::absolute::LockTime::ZERO);
        assert_eq!(transaction.input.len(), 1);
        assert_eq!(transaction.output.len(), 2);

        assert!(transaction.is_coinbase());

        let output = &transaction.output[0];
        assert_eq!(output.value, bitcoin::Amount::from_int_btc(SHARE_VALUE));
        assert_eq!(
            output.script_pubkey,
            ScriptBuf::new_witness_program(&address)
        );

        let commitment_output = &transaction.output[1];
        assert_eq!(commitment_output.value, bitcoin::Amount::ZERO);
        assert_eq!(
            commitment_output.script_pubkey.len(),
            WITNESS_COMMITMENT_LENGTH
        );
        assert_eq!(
            &commitment_output.script_pubkey.as_bytes()[..6],
            &BIP141_COMMITMENT_HEADER
        );

        let witness_stack: Vec<_> = transaction.input[0].witness.iter().collect();
        assert_eq!(witness_stack.len(), 1);
        assert_eq!(witness_stack[0], &WITNESS_RESERVED_VALUE);
    }

    #[test]
    fn test_create_share_block_coinbase_transaction_with_share_transactions() {
        let address = make_test_share_program(1);

        // Build two non-coinbase share transactions with distinct witnesses,
        // so each produces a different wtxid and contributes to the witness
        // root.
        let mut first_witness = bitcoin::Witness::new();
        first_witness.push([0xAAu8; 32]);
        let first_share_transaction = ShareTransaction(bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint {
                    txid: bitcoin::Txid::from_raw_hash(
                        <bitcoin::hashes::sha256d::Hash as Hash>::from_byte_array([0x11u8; 32]),
                    ),
                    vout: 0,
                },
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: first_witness,
            }],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(1_000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        });

        let mut second_witness = bitcoin::Witness::new();
        second_witness.push([0xBBu8; 32]);
        let second_share_transaction = ShareTransaction(bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint {
                    txid: bitcoin::Txid::from_raw_hash(
                        <bitcoin::hashes::sha256d::Hash as Hash>::from_byte_array([0x22u8; 32]),
                    ),
                    vout: 0,
                },
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: second_witness,
            }],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(2_000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        });

        let other_share_transactions = vec![first_share_transaction, second_share_transaction];
        let coinbase_transaction = build_sharechain_coinbase_transaction(
            &address,
            test_weak_block_hash(),
            &other_share_transactions,
        );

        assert_eq!(
            coinbase_transaction.version,
            bitcoin::transaction::Version::TWO
        );
        assert_eq!(
            coinbase_transaction.lock_time,
            bitcoin::absolute::LockTime::ZERO
        );
        assert_eq!(coinbase_transaction.input.len(), 1);
        assert_eq!(coinbase_transaction.output.len(), 2);
        assert!(coinbase_transaction.is_coinbase());

        let output = &coinbase_transaction.output[0];
        assert_eq!(output.value, bitcoin::Amount::from_int_btc(SHARE_VALUE));
        assert_eq!(
            output.script_pubkey,
            ScriptBuf::new_witness_program(&address)
        );

        let commitment_output = &coinbase_transaction.output[1];
        assert_eq!(commitment_output.value, bitcoin::Amount::ZERO);
        assert_eq!(
            commitment_output.script_pubkey.len(),
            WITNESS_COMMITMENT_LENGTH
        );
        assert_eq!(
            &commitment_output.script_pubkey.as_bytes()[..6],
            &BIP141_COMMITMENT_HEADER
        );

        // Recompute the commitment independently and verify it matches the
        // one embedded in the coinbase output.
        let expected_root = compute_witness_root(&other_share_transactions);
        let expected_hash = compute_commitment_hash(&expected_root, &WITNESS_RESERVED_VALUE);
        assert_eq!(
            &commitment_output.script_pubkey.as_bytes()[6..],
            expected_hash.as_byte_array()
        );

        // Commitment must differ from the empty-transactions case, proving
        // the witness root actually covers the share transactions.
        let empty_transaction =
            build_sharechain_coinbase_transaction(&address, test_weak_block_hash(), &[]);
        assert_ne!(
            commitment_output.script_pubkey,
            empty_transaction.output[1].script_pubkey
        );

        let witness_stack: Vec<_> = coinbase_transaction.input[0].witness.iter().collect();
        assert_eq!(witness_stack.len(), 1);
        assert_eq!(witness_stack[0], &WITNESS_RESERVED_VALUE);
    }
}

#[cfg(test)]
mod share_coinbase_tests {
    use super::tests::test_weak_block_hash;
    use super::*;
    use crate::test_utils::make_test_share_program;

    /// A non-coinbase share transaction spending a distinct outpoint, so it has
    /// its own txid and moves the root.
    fn share_transaction(previous_txid_byte: u8, value_sats: u64) -> ShareTransaction {
        ShareTransaction(Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint {
                    txid: bitcoin::Txid::from_byte_array([previous_txid_byte; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![TxOut {
                value: bitcoin::Amount::from_sat(value_sats),
                script_pubkey: ScriptBuf::new_witness_program(&make_test_share_program(2)),
            }],
        })
    }

    /// Two shares from one miner differ only
    /// in the block they were found for, so without the weak block hash in the
    /// coinbase they carry one txid and their share units collide on a single
    /// outpoint -- a miner with ten thousand shares would hold one unit.
    #[test]
    fn two_shares_from_one_miner_have_different_coinbase_txids() {
        let address = make_test_share_program(1);

        let first = build_sharechain_coinbase_transaction(
            &address,
            BlockHash::from_byte_array([0xaa; 32]),
            &[],
        );
        let second = build_sharechain_coinbase_transaction(
            &address,
            BlockHash::from_byte_array([0xbb; 32]),
            &[],
        );

        assert_ne!(first.compute_txid(), second.compute_txid());
    }

    /// Reconstruction during validation has to land on the same bytes, so the
    /// same inputs must always give the same transaction.
    #[test]
    fn coinbase_is_deterministic_for_the_same_inputs() {
        let address = make_test_share_program(1);
        assert_eq!(
            build_sharechain_coinbase_transaction(&address, test_weak_block_hash(), &[]),
            build_sharechain_coinbase_transaction(&address, test_weak_block_hash(), &[])
        );
    }

    /// Two miners must never produce interchangeable coinbases, or either could
    /// claim the other's share unit.
    #[test]
    fn different_miners_give_different_coinbase_txids() {
        let first = build_sharechain_coinbase_transaction(
            &make_test_share_program(1),
            test_weak_block_hash(),
            &[],
        );
        let second = build_sharechain_coinbase_transaction(
            &make_test_share_program(2),
            test_weak_block_hash(),
            &[],
        );

        assert_ne!(first.compute_txid(), second.compute_txid());
    }

    /// The coinbase commits to the other transactions through its BIP141
    /// witness commitment output, so its own txid moves when they change.
    #[test]
    fn coinbase_txid_depends_on_the_other_transactions() {
        let address = make_test_share_program(1);
        let alone = build_sharechain_coinbase_transaction(&address, test_weak_block_hash(), &[]);
        let with_transaction = build_sharechain_coinbase_transaction(
            &address,
            test_weak_block_hash(),
            &[share_transaction(0x11, 1_000)],
        );

        assert_ne!(alone.compute_txid(), with_transaction.compute_txid());
    }

    /// A share block carries only its coinbase today, so this is the value the
    /// commitment actually digests on every share. It is a convention rather
    /// than a computed root, because the merkle root of an empty tree is
    /// undefined.
    #[test]
    fn non_coinbase_root_is_all_zeros_without_share_transactions() {
        assert_eq!(
            compute_non_coinbase_root(&[]),
            TxMerkleNode::from_raw_hash(Hash::all_zeros())
        );
    }

    #[test]
    fn adding_a_share_transaction_changes_the_non_coinbase_root() {
        assert_ne!(
            compute_non_coinbase_root(&[]),
            compute_non_coinbase_root(&[share_transaction(0x11, 1_000)])
        );
    }

    /// Order is part of what the commitment binds: two blocks with the same
    /// transactions in a different order are different blocks.
    #[test]
    fn transaction_order_changes_the_non_coinbase_root() {
        let first = share_transaction(0x11, 1_000);
        let second = share_transaction(0x22, 2_000);

        assert_ne!(
            compute_non_coinbase_root(&[first.clone(), second.clone()]),
            compute_non_coinbase_root(&[second, first])
        );
    }

    /// The non-coinbase root deliberately excludes the coinbase, which is what
    /// lets the coinbase carry a value that does not exist until the work is
    /// done.
    #[test]
    fn non_coinbase_root_ignores_the_weak_block_hash() {
        let transactions = [share_transaction(0x11, 1_000)];
        assert_eq!(
            compute_non_coinbase_root(&transactions),
            compute_non_coinbase_root(&transactions)
        );
    }
}
