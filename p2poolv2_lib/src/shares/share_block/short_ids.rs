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

use bitcoin::bip152::{PrefilledTransaction, ShortId};
use bitcoin::consensus::{Decodable, Encodable};

/// Struct for bitcoin short IDs, and prefilled transactions, if any.
///
/// A [ShortIds] structure is used to relay a weak compact block as a
/// share.
///
/// The short transactions IDs used for matching already-available
/// transactions.
///
/// Just like rust-bitcoin's HeaderAndShortIds, the struct includes
/// nonce, vector of shortids and a vector of prefilled transactions.
/// In other words, this the same as HeaderAndShortIds, except that
/// the Header is missing. The Header is instead in the ShareHeader.
#[derive(Clone, PartialEq, Debug)]
pub struct ShortIds {
    ///  A nonce for use in short transaction ID calculations.
    pub nonce: u64,
    ///  The short transaction IDs calculated from the transa[ctions
    ///  which were not provided explicitly in prefilled_txs.
    pub short_ids: Vec<ShortId>,
    ///  Used to provide the coinbase transaction and a select few
    ///  which we expect a peer may be missing.
    pub prefilled_txs: Vec<PrefilledTransaction>,
}

impl Encodable for ShortIds {
    #[inline]
    fn consensus_encode<W: bitcoin::io::Write + ?Sized>(
        &self,
        w: &mut W,
    ) -> Result<usize, bitcoin::io::Error> {
        let mut len = 0;
        len += self.nonce.consensus_encode(w)?;
        len += self.short_ids.consensus_encode(w)?;
        len += self.prefilled_txs.consensus_encode(w)?;
        Ok(len)
    }
}

impl Decodable for ShortIds {
    #[inline]
    fn consensus_decode<R: bitcoin::io::Read + ?Sized>(
        r: &mut R,
    ) -> Result<Self, bitcoin::consensus::encode::Error> {
        Ok(ShortIds {
            nonce: Decodable::consensus_decode(r)?,
            short_ids: Decodable::consensus_decode(r)?,
            prefilled_txs: Decodable::consensus_decode(r)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::consensus::{deserialize, serialize};

    fn create_short_id(value: u64) -> ShortId {
        let mut bytes = [0u8; 6];
        bytes.copy_from_slice(&value.to_le_bytes()[..6]);
        ShortId::from(bytes)
    }

    #[test]
    fn test_short_ids_roundtrip() {
        let short_ids = ShortIds {
            nonce: 12345u64,
            short_ids: vec![create_short_id(1), create_short_id(2), create_short_id(3)],
            prefilled_txs: vec![],
        };

        let encoded = serialize(&short_ids);
        let decoded: ShortIds = deserialize(&encoded).unwrap();

        assert_eq!(short_ids, decoded);
    }

    #[test]
    fn test_short_ids_with_prefilled_txs_roundtrip() {
        use bitcoin::absolute::LockTime;
        use bitcoin::transaction::Version;
        use bitcoin::{Amount, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};

        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: bitcoin::OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_0000_0000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let short_ids = ShortIds {
            nonce: 67890u64,
            short_ids: vec![create_short_id(10), create_short_id(20)],
            prefilled_txs: vec![
                PrefilledTransaction {
                    idx: 0,
                    tx: tx.clone(),
                },
                PrefilledTransaction { idx: 2, tx: tx },
            ],
        };

        let encoded = serialize(&short_ids);
        let decoded: ShortIds = deserialize(&encoded).unwrap();

        assert_eq!(short_ids, decoded);
    }

    #[test]
    fn test_short_ids_empty_roundtrip() {
        let short_ids = ShortIds {
            nonce: 0u64,
            short_ids: vec![],
            prefilled_txs: vec![],
        };

        let encoded = serialize(&short_ids);
        let decoded: ShortIds = deserialize(&encoded).unwrap();

        assert_eq!(short_ids, decoded);
    }
}
