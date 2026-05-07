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
use bitcoin::{Address, Transaction, TxOut, WitnessMerkleNode, Wtxid, merkle_tree};

const SHARE_VALUE: u64 = 1; // 100_000_000 satoshi == 1 BTC == 1 share
/// BIP141 witness commitment header: OP_RETURN, push 36, magic "aa21a9ed".
const BIP141_COMMITMENT_HEADER: [u8; 6] = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
/// Witness reserved value (BIP141): 32 zero bytes, stored as the sole
/// witness stack item of the coinbase input.
const WITNESS_RESERVED_VALUE: [u8; 32] = [0u8; 32];

/// Create a coinbase transaction for the given bitcoin address.
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
    btcaddress: &Address,
    other_share_transactions: &[ShareTransaction],
) -> Transaction {
    let script_pubkey = btcaddress.script_pubkey();

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
    use bitcoin::{CompressedPublicKey, Network};

    #[test]
    fn test_create_share_block_coinbase_transaction() {
        let pubkey = "020202020202020202020202020202020202020202020202020202020202020202"
            .parse::<CompressedPublicKey>()
            .unwrap();
        let address = Address::p2wpkh(&pubkey, Network::Regtest);

        let transaction = build_sharechain_coinbase_transaction(&address, &[]);

        assert_eq!(transaction.version, bitcoin::transaction::Version::TWO);
        assert_eq!(transaction.lock_time, bitcoin::absolute::LockTime::ZERO);
        assert_eq!(transaction.input.len(), 1);
        assert_eq!(transaction.output.len(), 2);

        assert!(transaction.is_coinbase());

        let output = &transaction.output[0];
        assert_eq!(output.value, bitcoin::Amount::from_int_btc(SHARE_VALUE));
        assert_eq!(output.script_pubkey, address.script_pubkey());

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
        let pubkey = "020202020202020202020202020202020202020202020202020202020202020202"
            .parse::<CompressedPublicKey>()
            .unwrap();
        let address = Address::p2wpkh(&pubkey, Network::Regtest);

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
        assert_eq!(output.script_pubkey, address.script_pubkey());

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
