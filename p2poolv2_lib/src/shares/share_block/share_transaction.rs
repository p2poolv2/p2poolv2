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

use bitcoin::consensus::{Decodable, Encodable};
use bitcoin::{OutPoint, Transaction, Txid};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::ops::{Deref, DerefMut};

/// A transaction on the share chain.
///
/// Wraps a bitcoin::Transaction to provide type safety, distinguishing
/// share chain transactions from bitcoin block transactions.
///
/// Deref and encoding traits are implemented to support easier access
/// to Transaction methods and serde
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ShareTransaction(pub Transaction);

impl Deref for ShareTransaction {
    type Target = Transaction;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for ShareTransaction {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Encodable for ShareTransaction {
    #[inline]
    fn consensus_encode<W: bitcoin::io::Write + ?Sized>(
        &self,
        w: &mut W,
    ) -> Result<usize, bitcoin::io::Error> {
        self.0.consensus_encode(w)
    }
}

impl Decodable for ShareTransaction {
    #[inline]
    fn consensus_decode<R: bitcoin::io::Read + ?Sized>(
        r: &mut R,
    ) -> Result<Self, bitcoin::consensus::encode::Error> {
        Ok(ShareTransaction(Transaction::consensus_decode(r)?))
    }
}

/// The prevouts spent by a share block's non-coinbase inputs, together with the
/// external source txids (a source txid not produced by an earlier transaction
/// in the same block).
#[derive(Debug)]
pub struct SpendingPrevouts {
    pub all_outpoints: Vec<OutPoint>,
    pub external_source_txids: Vec<Txid>,
}

/// A prevout spent by more than one input within the same share block.
#[derive(Debug, thiserror::Error)]
#[error("Duplicate prevout {outpoint} spent by two inputs in the same share block")]
pub struct DuplicatePrevoutError {
    pub outpoint: OutPoint,
}

/// Extract the spending prevouts and external source txids from a block's
/// transactions.
///
/// Applies the in-block source-txid exemption: an input whose source txid is an
/// earlier transaction in the same block is not counted as an external source,
/// because that producer is introduced atomically with its spender. Returns
/// `DuplicatePrevoutError` if a prevout is spent by more than one input in the
/// block.
///
/// Shared by ingest prevout validation and the confirmation-time re-check so the
/// extraction logic exists once.
pub fn extract_spending_prevouts(
    transactions: &[ShareTransaction],
) -> Result<SpendingPrevouts, DuplicatePrevoutError> {
    let total_inputs: usize = transactions
        .iter()
        .map(|share_transaction| share_transaction.0.input.len())
        .sum();
    let mut all_outpoints: Vec<OutPoint> = Vec::with_capacity(total_inputs);
    let mut external_source_txids: HashSet<Txid> = HashSet::with_capacity(total_inputs);
    let mut seen_prevouts: HashSet<OutPoint> = HashSet::with_capacity(total_inputs);
    let mut in_block_txids: HashSet<Txid> = HashSet::with_capacity(transactions.len());
    for share_transaction in transactions {
        let transaction = &share_transaction.0;
        if !transaction.is_coinbase() {
            for input in &transaction.input {
                let outpoint = input.previous_output;
                if !seen_prevouts.insert(outpoint) {
                    return Err(DuplicatePrevoutError { outpoint });
                }
                all_outpoints.push(outpoint);
                if !in_block_txids.contains(&outpoint.txid) {
                    external_source_txids.insert(outpoint.txid);
                }
            }
        }
        in_block_txids.insert(transaction.compute_txid());
    }
    Ok(SpendingPrevouts {
        all_outpoints,
        external_source_txids: external_source_txids.into_iter().collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::{Amount, ScriptBuf, Sequence, TxIn, TxOut, Witness};
    use bitcoin::{absolute::LockTime, transaction::Version};

    fn outpoint(source_byte: u8, vout: u32) -> OutPoint {
        OutPoint {
            txid: Txid::from_byte_array([source_byte; 32]),
            vout,
        }
    }

    /// A non-coinbase transaction spending the given outpoints. With a single
    /// null outpoint it becomes a coinbase (`OutPoint::null`).
    fn transaction_spending(prevouts: &[OutPoint]) -> ShareTransaction {
        let input = prevouts
            .iter()
            .map(|previous_output| TxIn {
                previous_output: *previous_output,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            })
            .collect();
        ShareTransaction(Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input,
            output: vec![TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: ScriptBuf::new(),
            }],
        })
    }

    fn coinbase() -> ShareTransaction {
        transaction_spending(&[OutPoint::null()])
    }

    #[test]
    fn test_extract_ignores_coinbase_only_block() {
        let result = extract_spending_prevouts(&[coinbase()]).unwrap();
        assert!(result.all_outpoints.is_empty());
        assert!(result.external_source_txids.is_empty());
    }

    #[test]
    fn test_extract_collects_distinct_external_sources() {
        let first = outpoint(1, 0);
        let second = outpoint(2, 0);
        let block = vec![coinbase(), transaction_spending(&[first, second])];

        let result = extract_spending_prevouts(&block).unwrap();

        assert_eq!(result.all_outpoints, vec![first, second]);
        let source_txids: HashSet<Txid> = result.external_source_txids.into_iter().collect();
        assert_eq!(source_txids, HashSet::from([first.txid, second.txid]));
    }

    #[test]
    fn test_extract_dedups_external_source_txids() {
        // Two outpoints of the same source transaction collapse to one txid.
        let first = outpoint(7, 0);
        let second = outpoint(7, 1);
        let block = vec![coinbase(), transaction_spending(&[first, second])];

        let result = extract_spending_prevouts(&block).unwrap();

        assert_eq!(result.all_outpoints, vec![first, second]);
        assert_eq!(result.external_source_txids, vec![first.txid]);
    }

    #[test]
    fn test_extract_exempts_in_block_source() {
        // A producer spends an external output; a later spender spends the
        // producer's output. The producer's txid is exempt from external
        // sources, but the in-block outpoint is still collected.
        let external = outpoint(3, 0);
        let producer = transaction_spending(&[external]);
        let producer_txid = producer.0.compute_txid();
        let in_block = OutPoint {
            txid: producer_txid,
            vout: 0,
        };
        let spender = transaction_spending(&[in_block]);
        let block = vec![coinbase(), producer, spender];

        let result = extract_spending_prevouts(&block).unwrap();

        assert_eq!(result.all_outpoints, vec![external, in_block]);
        assert_eq!(result.external_source_txids, vec![external.txid]);
        assert!(!result.external_source_txids.contains(&producer_txid));
    }

    #[test]
    fn test_extract_rejects_duplicate_prevout_within_tx() {
        let repeated = outpoint(4, 0);
        let block = vec![coinbase(), transaction_spending(&[repeated, repeated])];

        let error = extract_spending_prevouts(&block).unwrap_err();

        assert_eq!(error.outpoint, repeated);
    }

    #[test]
    fn test_extract_rejects_duplicate_prevout_across_txs() {
        let repeated = outpoint(5, 0);
        let block = vec![
            coinbase(),
            transaction_spending(&[repeated]),
            transaction_spending(&[repeated]),
        ];

        let error = extract_spending_prevouts(&block).unwrap_err();

        assert_eq!(error.outpoint, repeated);
    }
}
