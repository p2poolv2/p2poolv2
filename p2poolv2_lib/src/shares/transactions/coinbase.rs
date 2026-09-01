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
use bitcoin::{
    ScriptBuf, Transaction, TxMerkleNode, TxOut, WitnessMerkleNode, WitnessProgram, Wtxid,
    merkle_tree,
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
pub fn build_sharechain_coinbase_transaction(
    miner_address: &WitnessProgram,
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
        script_sig: bitcoin::ScriptBuf::new(),
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

/// Merkle root over a share's transactions, for the given miner address.
///
/// The share commitment is fixed at notify time, before the miner hashes, so
/// the root has to be computable then. Kept here beside the coinbase builder so
/// the notify path and the share assembly path cannot drift apart.
pub fn compute_share_merkle_root(
    miner_address: &WitnessProgram,
    other_share_transactions: &[ShareTransaction],
) -> TxMerkleNode {
    let coinbase = build_sharechain_coinbase_transaction(miner_address, other_share_transactions);
    let txids = std::iter::once(coinbase.compute_txid())
        .chain(
            other_share_transactions
                .iter()
                .map(|transaction| transaction.compute_txid()),
        )
        .map(|txid| txid.to_raw_hash());
    merkle_tree::calculate_root(txids)
        .map(TxMerkleNode::from_raw_hash)
        .expect("a share always has at least a coinbase")
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
    use crate::test_utils::make_test_share_program;

    #[test]
    fn test_create_share_block_coinbase_transaction() {
        let address = make_test_share_program(1);

        let transaction = build_sharechain_coinbase_transaction(&address, &[]);

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
        let transaction =
            build_sharechain_coinbase_transaction(&address, &other_share_transactions);

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
        let empty_transaction = build_sharechain_coinbase_transaction(&address, &[]);
        assert_ne!(
            commitment_output.script_pubkey,
            empty_transaction.output[1].script_pubkey
        );

        let witness_stack: Vec<_> = transaction.input[0].witness.iter().collect();
        assert_eq!(witness_stack.len(), 1);
        assert_eq!(witness_stack[0], &WITNESS_RESERVED_VALUE);
    }
}

#[cfg(test)]
mod share_merkle_root_tests {
    use super::*;
    use crate::test_utils::make_test_share_program;

    /// A non-coinbase share transaction spending a distinct outpoint, so it has
    /// its own txid and moves the merkle root.
    fn share_transaction(previous_txid_byte: u8, value_sats: u64) -> ShareTransaction {
        ShareTransaction(bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint {
                    txid: bitcoin::Txid::from_raw_hash(
                        <bitcoin::hashes::sha256d::Hash as Hash>::from_byte_array(
                            [previous_txid_byte; 32],
                        ),
                    ),
                    vout: 0,
                },
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(value_sats),
                script_pubkey: ScriptBuf::new_witness_program(&make_test_share_program(2)),
            }],
        })
    }

    /// With only the coinbase there is a single leaf, and BIP98 makes the root
    /// of a one-leaf tree the leaf itself.
    #[test]
    fn coinbase_only_root_is_the_coinbase_txid() {
        let address = make_test_share_program(1);
        let coinbase = build_sharechain_coinbase_transaction(&address, &[]);

        let root = compute_share_merkle_root(&address, &[]);

        assert_eq!(root.to_raw_hash(), coinbase.compute_txid().to_raw_hash());
    }

    #[test]
    fn root_is_deterministic_for_the_same_inputs() {
        let address = make_test_share_program(1);
        let transactions = vec![share_transaction(0x11, 1_000)];

        assert_eq!(
            compute_share_merkle_root(&address, &transactions),
            compute_share_merkle_root(&address, &transactions)
        );
    }

    /// The commitment binds the root instead of the share address, so the root
    /// is what distinguishes one miner's share from another's. If this ever
    /// held, two miners would produce interchangeable commitments and either
    /// could claim the other's share.
    #[test]
    fn different_share_addresses_give_different_roots() {
        let first = make_test_share_program(1);
        let second = make_test_share_program(2);
        assert_ne!(first, second);

        assert_ne!(
            compute_share_merkle_root(&first, &[]),
            compute_share_merkle_root(&second, &[])
        );
    }

    #[test]
    fn adding_a_share_transaction_changes_the_root() {
        let address = make_test_share_program(1);

        let coinbase_only = compute_share_merkle_root(&address, &[]);
        let with_transaction =
            compute_share_merkle_root(&address, &[share_transaction(0x11, 1_000)]);

        assert_ne!(coinbase_only, with_transaction);
    }

    #[test]
    fn transaction_order_changes_the_root() {
        let address = make_test_share_program(1);
        let first = share_transaction(0x11, 1_000);
        let second = share_transaction(0x22, 2_000);

        let forward = compute_share_merkle_root(&address, &[first.clone(), second.clone()]);
        let reversed = compute_share_merkle_root(&address, &[second, first]);

        assert_ne!(forward, reversed);
    }

    /// The commitment is built at notify time from the address alone, while the
    /// share is assembled later from the actual transaction list. Those two
    /// have to reach the same root or every share is rejected as committing to
    /// something other than what it contains.
    #[test]
    fn root_matches_the_root_of_the_assembled_transaction_list() {
        let address = make_test_share_program(1);
        let others = vec![
            share_transaction(0x11, 1_000),
            share_transaction(0x22, 2_000),
        ];

        let from_address = compute_share_merkle_root(&address, &others);

        // Assemble the block body the way the share path does: coinbase first,
        // then the other transactions in order.
        let coinbase = build_sharechain_coinbase_transaction(&address, &others);
        let mut assembled = Vec::with_capacity(1 + others.len());
        assembled.push(ShareTransaction(coinbase));
        assembled.extend(others);
        let from_assembled: TxMerkleNode =
            merkle_tree::calculate_root(assembled.iter().map(|tx| tx.compute_txid().to_raw_hash()))
                .map(TxMerkleNode::from_raw_hash)
                .unwrap();

        assert_eq!(from_address, from_assembled);
    }

    /// The coinbase commits to the other transactions through its BIP141
    /// witness commitment output, so its own txid moves when they change. This
    /// is why the root cannot be computed from the coinbase alone and then
    /// have transactions appended.
    #[test]
    fn coinbase_txid_depends_on_the_other_transactions() {
        let address = make_test_share_program(1);

        let alone = build_sharechain_coinbase_transaction(&address, &[]);
        let with_transaction =
            build_sharechain_coinbase_transaction(&address, &[share_transaction(0x11, 1_000)]);

        assert_ne!(alone.compute_txid(), with_transaction.compute_txid());
    }
}
