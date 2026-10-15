// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Miner-selected BCH coinbase bytes needed to reconstruct PPLNS payouts.

use super::merge_mining::MergeMiningCommitment;
use bitcoin::absolute::LockTime;
use bitcoin::consensus::encode::Error::ParseFailed;
use bitcoin::consensus::{Decodable, Encodable};
use bitcoin::script::Builder;
use serde::{Deserialize, Serialize};

/// A BCH declared coinbase ends its scriptSig with the 12-byte extranonce.
/// Version, sequence and locktime retain the pool's canonical values.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BchCoinbase {
    /// Raw scriptSig bytes before the extranonce, including BIP34 height.
    pub prefix: Vec<u8>,
    /// The one aux-tree commitment selected by this miner.
    pub merge_mining: MergeMiningCommitment,
}

impl BchCoinbase {
    /// Check the scriptSig budget and the canonical BIP34 height prefix.
    pub fn validate(&self, height: u64) -> Result<(), &'static str> {
        height
            .checked_sub(1)
            .and_then(|height| u32::try_from(height).ok())
            .and_then(|height| LockTime::from_height(height).ok())
            .ok_or("invalid declared BCH coinbase height")?;
        let height = i64::try_from(height).map_err(|_| "BCH height exceeds i64")?;
        let height_script = Builder::new().push_int(height).into_script();
        if self.prefix.len() > 88 || !self.prefix.starts_with(height_script.as_bytes()) {
            return Err("declared coinbase must begin with its BIP34 height and fit 100 bytes");
        }
        self.merge_mining.validate()
    }
}

impl Encodable for BchCoinbase {
    fn consensus_encode<W: bitcoin::io::Write + ?Sized>(
        &self,
        writer: &mut W,
    ) -> Result<usize, bitcoin::io::Error> {
        Ok(self.prefix.consensus_encode(writer)? + self.merge_mining.consensus_encode(writer)?)
    }
}

impl Decodable for BchCoinbase {
    fn consensus_decode<R: bitcoin::io::Read + ?Sized>(
        reader: &mut R,
    ) -> Result<Self, bitcoin::consensus::encode::Error> {
        let length = u8::consensus_decode(reader)?;
        if length > 88 {
            return Err(ParseFailed("declared coinbase prefix exceeds 88 bytes"));
        }
        let mut prefix = vec![0; usize::from(length)];
        reader.read_exact(&mut prefix)?;
        Ok(Self {
            prefix,
            merge_mining: MergeMiningCommitment::consensus_decode(reader)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounting::OutputPair;
    use crate::shares::coinbase_proof::CoinbaseProof;
    use crate::shares::share_block::{ShareBlock, ShareHeader};
    use crate::shares::share_commitment::ShareCommitment;
    use crate::stratum::work::coinbase::build_declared_coinbase;
    use crate::test_utils::{TestShareBlockBuilder, make_test_address};
    use bitcoin::consensus::{deserialize, serialize};
    use bitcoin::{Amount, TxMerkleNode};
    use p2poolv2_wallet::share_owner::ShareOwner;

    #[test]
    fn declared_bch_coinbase_round_trips_and_binds_the_miner_prefix_and_aux_tree() {
        let mut share = TestShareBlockBuilder::new().build();
        share.header.prev_share_blockhash = share.header.bitcoin_header.block_hash();
        share.header.miner_address = ShareOwner::CashP2pkh([0x22; 20]);
        share.header.bitcoin_height = 702;
        share.header.coinbase_nsecs = 0;
        share.header.coinbaseaux_flags = None;
        share.header.witness_commitment = None;
        let declared = BchCoinbase {
            prefix: Builder::new()
                .push_int(702)
                .push_slice(b"miner")
                .into_bytes(),
            merge_mining: MergeMiningCommitment {
                merkle_root: [0x33; 32],
                tree_size: 4,
                nonce: 7,
            },
        };
        share.header.bch_coinbase = Some(declared.clone());
        let coinbase = build_declared_coinbase(
            &[OutputPair {
                address: make_test_address(1),
                amount: Amount::from_sat(share.header.coinbase_value),
            }],
            702,
            ShareCommitment::from_share_block(&share).hash(),
            share.header.extranonce.as_bytes(),
            &declared,
        )
        .unwrap();
        share.header.coinbase_proof =
            CoinbaseProof::from_coinbase(&coinbase, share.header.coinbase_proof.non_coinbase_root)
                .unwrap();
        share.template_merkle_branches.clear();
        share.header.bitcoin_header.merkle_root =
            TxMerkleNode::from_raw_hash(coinbase.compute_txid().to_raw_hash());
        CoinbaseProof::verify(&share.header, &[]).unwrap();
        let decoded: ShareBlock = deserialize(&serialize(&share)).unwrap();
        assert_eq!(decoded, share);
        let header: ShareHeader = deserialize(&serialize(&share.header)).unwrap();
        assert_eq!(header, share.header);
        let old_encoding = serialize(&share.header);
        share.header.bch_coinbase = None;
        assert_ne!(serialize(&share.header), old_encoding);
        assert_eq!(
            deserialize::<ShareHeader>(&serialize(&share.header)).unwrap(),
            share.header
        );
        share.header.bch_coinbase = Some(declared);
        share
            .header
            .bch_coinbase
            .as_mut()
            .unwrap()
            .merge_mining
            .nonce += 1;
        assert!(CoinbaseProof::verify(&share.header, &[]).is_err());
        share
            .header
            .bch_coinbase
            .as_mut()
            .unwrap()
            .merge_mining
            .nonce -= 1;
        share.header.bch_coinbase.as_mut().unwrap().prefix.push(0);
        assert!(CoinbaseProof::verify(&share.header, &[]).is_err());
        share.header.bch_coinbase.as_mut().unwrap().prefix.pop();
        share.header.coinbase_nsecs = 1;
        assert!(CoinbaseProof::verify(&share.header, &[]).is_err());
    }

    #[test]
    fn declared_bch_prefix_must_fit_the_scriptsig_and_start_with_height() {
        let mut declared = BchCoinbase {
            prefix: vec![0x51; 88],
            merge_mining: MergeMiningCommitment::reserved(),
        };
        assert!(declared.validate(1).is_ok());
        assert!(declared.validate(0).is_err());
        assert!(declared.validate(u64::MAX).is_err());
        declared.prefix.push(0x51);
        assert!(declared.validate(1).is_err());
        assert!(deserialize::<BchCoinbase>(&serialize(&declared)).is_err());
        declared.prefix = vec![0x52];
        assert!(declared.validate(1).is_err());
    }

    #[test]
    fn a_bitcoin_owner_cannot_encode_a_declared_bch_header() {
        let mut header = TestShareBlockBuilder::new().build().header;
        header.prev_share_blockhash = header.bitcoin_header.block_hash();
        header.bch_coinbase = Some(BchCoinbase {
            prefix: vec![0x51],
            merge_mining: MergeMiningCommitment::reserved(),
        });
        assert!(deserialize::<ShareHeader>(&serialize(&header)).is_err());
        assert!(CoinbaseProof::verify(&header, &[]).is_err());
    }

    #[test]
    fn aux_tree_width_and_empty_tree_are_unambiguous() {
        let mut commitment = MergeMiningCommitment {
            merkle_root: [0x33; 32],
            tree_size: 3,
            nonce: 7,
        };
        assert!(commitment.validate().is_err());
        commitment.tree_size = 0;
        assert!(commitment.validate().is_err());
        commitment.tree_size = 4;
        assert!(commitment.validate().is_ok());
        assert_eq!(
            deserialize::<MergeMiningCommitment>(&serialize(&commitment)).unwrap(),
            commitment
        );
    }
}
