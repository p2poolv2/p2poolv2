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

pub mod share_coinbase;
pub mod share_transaction;
pub mod short_ids;
pub mod storage_share_block;

use super::transactions;
use crate::shares::genesis;
use crate::shares::share_commitment::ShareCommitment;
use bitcoin::{
    Block, BlockHash, CompactTarget, CompressedPublicKey, Target, Transaction, TxMerkleNode, Txid,
    VarInt, bip152,
    block::Header,
    consensus::{Decodable, Encodable},
    hashes::Hash,
};
use core::mem;
use serde::{Deserialize, Serialize};
pub use share_transaction::ShareTransaction;
use std::error::Error;
pub use storage_share_block::StorageShareBlock;

/// Header for the share chain block.
///
/// Exludes bitcoin compact block and share chain transactions.
/// Includes the bitcoin block hash for the bitcoin compact block instead.
///
/// TODO(pool2win): Add the donation and fee details used to build the coinbase.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ShareHeader {
    /// The hash of the prev share block, will be None for genesis block
    pub prev_share_blockhash: BlockHash,
    /// The uncles of the share
    pub uncles: Vec<BlockHash>,
    /// Compressed pubkey identifying the miner
    pub miner_pubkey: CompressedPublicKey,
    /// Share block transactions merkle root
    pub merkle_root: TxMerkleNode,
    /// Bitcoin header the share is found for
    pub bitcoin_header: Header,
    /// Share chain difficult as compact target
    pub bits: CompactTarget,
    /// Timestamp for the share, as set by the miner
    pub time: u32,
}

impl ShareHeader {
    /// Get the work defined by the bits field
    pub(crate) fn get_work(&self) -> bitcoin::Work {
        Target::from_compact(self.bits).to_work()
    }

    /// Build a ShareHeader from a commitment and a bitcoin header
    /// which contains a coinbase matching the commitment.
    ///
    /// We do not validate the commitment is actually present in the
    /// bitcoin header. That happens at the receiving node.
    pub(crate) fn from_commitment_and_header(
        commitment: ShareCommitment,
        bitcoin_header: Header,
        share_chain_merkle_root: TxMerkleNode,
    ) -> Self {
        Self {
            prev_share_blockhash: commitment.prev_share_blockhash,
            uncles: commitment.uncles,
            miner_pubkey: commitment.miner_pubkey,
            merkle_root: share_chain_merkle_root,
            bitcoin_header,
            bits: commitment.bits,
            time: commitment.time,
        }
    }

    /// Block hash for the share header
    pub fn block_hash(&self) -> BlockHash {
        let mut engine = BlockHash::engine();
        self.consensus_encode(&mut engine)
            .expect("engines don't error");
        BlockHash::from_engine(engine)
    }

    /// Generate a commitment hash serialized using consensus encode
    ///
    /// Serialize all fields in ShareHeader apart from bitcoin_header
    /// and return a sha256 of the serialized bytes
    pub fn commitment_hash(&self) -> Result<bitcoin::hashes::sha256::Hash, Box<dyn Error>> {
        let mut serialized_without_bitcoin_header = Vec::new();
        self.prev_share_blockhash
            .consensus_encode(&mut serialized_without_bitcoin_header)?;
        self.uncles
            .consensus_encode(&mut serialized_without_bitcoin_header)?;
        self.miner_pubkey
            .write_into(&mut serialized_without_bitcoin_header)?;
        self.merkle_root
            .consensus_encode(&mut serialized_without_bitcoin_header)?;
        self.bits
            .consensus_encode(&mut serialized_without_bitcoin_header)?;
        self.time
            .consensus_encode(&mut serialized_without_bitcoin_header)?;

        Ok(bitcoin::hashes::sha256::Hash::hash(
            &serialized_without_bitcoin_header,
        ))
    }
}

impl Encodable for ShareHeader {
    #[inline]
    fn consensus_encode<W: bitcoin::io::Write + ?Sized>(
        &self,
        w: &mut W,
    ) -> Result<usize, bitcoin::io::Error> {
        let mut len = 0;
        len += self.prev_share_blockhash.consensus_encode(w)?;
        len += self.uncles.consensus_encode(w)?;
        self.miner_pubkey.write_into(w)?;
        len += 33; // Compressedpublickey is 33 bytes
        len += self.merkle_root.consensus_encode(w)?;
        len += self.bitcoin_header.consensus_encode(w)?;
        len += self.bits.consensus_encode(w)?;
        len += self.time.consensus_encode(w)?;
        Ok(len)
    }
}

impl Decodable for ShareHeader {
    #[inline]
    fn consensus_decode<R: bitcoin::io::Read + ?Sized>(
        r: &mut R,
    ) -> Result<Self, bitcoin::consensus::encode::Error> {
        Ok(ShareHeader {
            prev_share_blockhash: BlockHash::consensus_decode(r)?,
            uncles: Vec::<BlockHash>::consensus_decode(r)?,
            miner_pubkey: CompressedPublicKey::read_from(r)?,
            merkle_root: TxMerkleNode::consensus_decode(r)?,
            bitcoin_header: Header::consensus_decode(r)?,
            bits: CompactTarget::consensus_decode(r)?,
            time: u32::consensus_decode(r)?,
        })
    }
}

/// Captures a block on the share chain.
///
/// This captures the share chain header and the list of transactions
/// for the share chain, as well as bitcoin compact block.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ShareBlock {
    /// Header for the block
    pub header: ShareHeader,
    /// Share chain transactions - including the coinbase for the share.
    pub transactions: Vec<ShareTransaction>,
    /// Bitcoin transactions, making for a full share block.
    /// Optimisations for storage and communication are left elsewhere as they are two different optimisations.
    pub bitcoin_transactions: Vec<Transaction>,
}

impl ShareBlock {
    /// Get difficulty for share header with given bitcoin network
    pub fn get_difficulty(&self, network: bitcoin::Network) -> u128 {
        self.header.bitcoin_header.difficulty(network)
    }

    /// Build a new ShareBlock from the found bitcoin block and share chain metadata
    ///
    /// Share chain metadata includes previous block hash, uncles and
    /// transactions included in the share chain block.
    ///
    /// Miner pub key identifies the miner that found the share and is used to build the coinbase for the share block.
    pub fn new(
        bitcoin_block: Block,
        prev_share_blockhash: BlockHash,
        uncles: &[BlockHash],
        miner_pubkey: CompressedPublicKey,
        transactions: Vec<ShareTransaction>,
        network: bitcoin::Network,
    ) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let coinbase = transactions::coinbase::create_coinbase_transaction(&miner_pubkey, network);
        let mut all_transactions = vec![ShareTransaction(coinbase)];
        all_transactions.extend(transactions);
        let merkle_root: TxMerkleNode = bitcoin::merkle_tree::calculate_root(
            all_transactions.iter().map(|tx| tx.compute_txid()),
        )
        .unwrap()
        .into();

        let header = ShareHeader {
            prev_share_blockhash,
            uncles: uncles.to_vec(),
            miner_pubkey,
            bitcoin_header: bitcoin_block.header,
            merkle_root,
            time: 1700000000u32,
            bits: CompactTarget::from_consensus(0x207fffff),
        };
        Ok(Self {
            header,
            transactions: all_transactions,
            bitcoin_transactions: bitcoin_block.txdata,
        })
    }

    /// Compute and return the block hash for this share block
    pub fn block_hash(&self) -> BlockHash {
        self.header.block_hash()
    }

    /// Build a genesis share block for a given network
    /// The bitcoin blockhash is hardcoded, so are the coinbase, nonce2, nonce, ntime, diff
    /// The workinfoid and clientid are 0 for genesis block on all networks
    pub fn build_genesis_for_network(network: bitcoin::Network) -> Self {
        assert!(
            network == bitcoin::Network::Signet
                || network == bitcoin::Network::Testnet4
                || network == bitcoin::Network::Bitcoin,
            "Network Testnet and Regtest not yet supported"
        );
        let genesis_data = genesis::genesis_data(network).unwrap();
        ShareBlock::build_genesis(&genesis_data, network)
    }

    /// Build a genesis share chain block from the genesis data
    /// available in the source code.
    ///
    /// Uses network to create coinbase transaction for miner that
    /// mined genesis block. This is a NUMPS miner pubkey.
    fn build_genesis(genesis_data: &genesis::GenesisData, network: bitcoin::Network) -> Self {
        let public_key = genesis_data
            .public_key
            .parse::<CompressedPublicKey>()
            .unwrap();
        let coinbase_tx = transactions::coinbase::create_coinbase_transaction(&public_key, network);
        let transactions = vec![ShareTransaction(coinbase_tx)];
        let merkle_root: TxMerkleNode =
            bitcoin::merkle_tree::calculate_root(transactions.iter().map(|tx| tx.compute_txid()))
                .unwrap()
                .into();
        let block_hex = hex::decode(genesis_data.bitcoin_block_hex).unwrap();
        // panic here, as if the genesis block is bad, we bail at the start of the process
        let compact_block: bip152::HeaderAndShortIds =
            match bitcoin::consensus::deserialize(&block_hex) {
                Ok(block) => block,
                Err(e) => {
                    println!("Failed to deserialize genesis block: {e}");
                    panic!("Invalid genesis block data");
                }
            };
        let header = ShareHeader {
            prev_share_blockhash: BlockHash::all_zeros(),
            uncles: vec![],
            miner_pubkey: public_key,
            bitcoin_header: compact_block.header,
            merkle_root,
            time: 1700000000u32,
            bits: CompactTarget::from_consensus(0x207fffff),
        };
        Self {
            header,
            transactions,
            // TODO: Initial plan was to rehydrate Block from Headerandshortids and use Block::txdata,
            // Instead we need to only place short ids here. Still a todo!
            bitcoin_transactions: vec![],
        }
    }
}

/// Encode ShareBlock using rust-bitcoin Encodable support
///
/// We have a new type ShareTransaction and have to encode a vector of
/// `transactions` manually. The `bitcoin_transactions` is a vector of
/// Transaction and rust-bitcoin provides encoding for vec of their
/// types out of the box.
impl Encodable for ShareBlock {
    fn consensus_encode<W: bitcoin::io::Write + ?Sized>(
        &self,
        w: &mut W,
    ) -> Result<usize, bitcoin::io::Error> {
        let mut len = 0;
        len += self.header.consensus_encode(w)?;
        // Encode share transactions
        len += VarInt(self.transactions.len() as u64).consensus_encode(w)?;
        for tx in &self.transactions {
            len += tx.consensus_encode(w)?;
        }
        len += self.bitcoin_transactions.consensus_encode(w)?;
        Ok(len)
    }
}

/// Decode ShareBlock using rust-bitcoin.
///
/// See comment on Encodable for handling `transactions` vs `bitcoin_transactions`
impl Decodable for ShareBlock {
    fn consensus_decode<R: bitcoin::io::Read + ?Sized>(
        r: &mut R,
    ) -> Result<Self, bitcoin::consensus::encode::Error> {
        let header = ShareHeader::consensus_decode(r)?;
        // Decode share transactions
        let tx_count = VarInt::consensus_decode(r)?.0 as usize;
        let max_capacity =
            bitcoin::consensus::encode::MAX_VEC_SIZE / 4 / mem::size_of::<ShareTransaction>();
        let mut transactions = Vec::with_capacity(core::cmp::min(tx_count, max_capacity));
        for _ in 0..tx_count {
            transactions.push(ShareTransaction::consensus_decode(r)?);
        }
        let bitcoin_transactions = Vec::<Transaction>::consensus_decode(r)?;
        Ok(ShareBlock {
            header,
            transactions,
            bitcoin_transactions,
        })
    }
}

/// A new type for vector of txids.
/// We then provide Encodable/Decodable for this.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Txids(pub Vec<Txid>);

impl Encodable for Txids {
    #[inline]
    fn consensus_encode<W: bitcoin::io::Write + ?Sized>(
        &self,
        w: &mut W,
    ) -> Result<usize, bitcoin::io::Error> {
        let mut len = 0;
        len += VarInt(self.0.len() as u64).consensus_encode(w)?;
        for c in self.0.iter() {
            len += c.consensus_encode(w)?;
        }
        Ok(len)
    }
}

impl Decodable for Txids {
    #[inline]
    fn consensus_decode_from_finite_reader<R: bitcoin::io::Read + ?Sized>(
        r: &mut R,
    ) -> Result<Self, bitcoin::consensus::encode::Error> {
        let len = VarInt::consensus_decode_from_finite_reader(r)?.0;
        // Do not allocate upfront more items than if the sequence of type
        // occupied roughly quarter a block. This should never be the case
        // for normal data, but even if that's not true - `push` will just
        // reallocate.
        // Note: OOM protection relies on reader eventually running out of
        // data to feed us.
        let max_capacity = bitcoin::consensus::encode::MAX_VEC_SIZE / 4 / mem::size_of::<Txid>();
        let mut ret = Txids(Vec::with_capacity(core::cmp::min(
            len as usize,
            max_capacity,
        )));
        for _ in 0..len {
            ret.0
                .push(Decodable::consensus_decode_from_finite_reader(r)?);
        }
        Ok(ret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TestShareBlockBuilder;
    use bitcoin::consensus::{deserialize, serialize};
    use std::str::FromStr;

    #[test]
    fn test_build_genesis_share_header() {
        let share = ShareBlock::build_genesis_for_network(bitcoin::Network::Signet);

        assert!(share.header.uncles.is_empty());
        assert_eq!(
            share.header.miner_pubkey.to_string(),
            "02ac493f2130ca56cb5c3a559860cef9a84f90b5a85dfe4ec6e6067eeee17f4d2d"
        );
        assert_eq!(share.transactions.len(), 1);
        assert!(share.transactions[0].is_coinbase());
        assert_eq!(share.transactions[0].output.len(), 1);
        assert_eq!(share.transactions[0].input.len(), 1);

        let output = &share.transactions[0].output[0];
        assert_eq!(output.value.to_sat(), 100_000_000);

        let expected_address = bitcoin::Address::p2pkh(
            "02ac493f2130ca56cb5c3a559860cef9a84f90b5a85dfe4ec6e6067eeee17f4d2d"
                .parse::<CompressedPublicKey>()
                .unwrap(),
            bitcoin::Network::Signet,
        );
        assert_eq!(output.script_pubkey, expected_address.script_pubkey());
        assert_eq!(
            share.header.bitcoin_header.block_hash().to_string(),
            "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6"
        );
    }

    #[test]
    fn test_share_block_new_includes_coinbase_transaction() {
        // Create a test public key
        let pubkey = "020202020202020202020202020202020202020202020202020202020202020202"
            .parse::<CompressedPublicKey>()
            .unwrap();

        let share_block = TestShareBlockBuilder::new().build();

        // Verify the coinbase transaction exists and has expected properties
        assert!(share_block.transactions[0].is_coinbase());
        assert_eq!(share_block.transactions[0].output.len(), 1);
        assert_eq!(share_block.transactions[0].input.len(), 1);

        // Verify the output is a P2PKH to the miner's public key
        let output = &share_block.transactions[0].output[0];
        assert_eq!(output.value.to_sat(), 100_000_000);

        // Verify the output script is P2PKH for the miner's pubkey
        let expected_address = bitcoin::Address::p2pkh(pubkey, bitcoin::Network::Regtest);
        assert_eq!(output.script_pubkey, expected_address.script_pubkey());
    }

    #[test]
    fn test_share_block_new() {
        // Create test data
        let prev_share_blockhash =
            "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb4";
        let uncles = vec![
            BlockHash::from_str("00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6")
                .unwrap(),
        ];
        let miner_pubkey = "020202020202020202020202020202020202020202020202020202020202020202";

        // Create a bitcoin block header
        let share_block = TestShareBlockBuilder::new()
            .prev_share_blockhash(prev_share_blockhash.into())
            .uncles(uncles)
            .miner_pubkey(miner_pubkey)
            .build();

        // Verify transactions include coinbase
        assert_eq!(share_block.transactions.len(), 1);
        assert!(share_block.transactions[0].is_coinbase());

        // Verify merkle root is correctly calculated
        let expected_merkle_root: TxMerkleNode = bitcoin::merkle_tree::calculate_root(
            share_block.transactions.iter().map(|tx| tx.compute_txid()),
        )
        .unwrap()
        .into();
        assert_eq!(share_block.header.merkle_root, expected_merkle_root);
    }

    #[test]
    fn test_commitment_hash() {
        let share = TestShareBlockBuilder::new()
            .prev_share_blockhash(
                "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb4".to_string(),
            )
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .work(1)
            .build();

        let hash = share.header.commitment_hash().unwrap();
        assert_eq!(hash.to_string().len(), 64); // SHA256d hash is 64 hex chars
    }

    #[test]
    fn test_commitment_hash_excludes_bitcoin_header() {
        let bitcoin_header = TestShareBlockBuilder::new()
            .work(2)
            .build()
            .header
            .bitcoin_header;

        let prev_hash =
            "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb4".to_string();
        let pubkey = "020202020202020202020202020202020202020202020202020202020202020202";

        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(prev_hash.clone())
            .miner_pubkey(pubkey)
            .work(1)
            .build();

        let mut share2 = share1.clone();
        share2.header.bitcoin_header = bitcoin_header;

        let hash1 = share1.header.commitment_hash().unwrap();
        let hash2 = share2.header.commitment_hash().unwrap();

        assert_eq!(
            hash1, hash2,
            "Commitment hash should be the same even with different bitcoin headers"
        );
    }

    #[test]
    fn test_from_commitment_and_header() {
        let bitcoin_header = TestShareBlockBuilder::new().build().header.bitcoin_header;
        let commitment = ShareCommitment {
            prev_share_blockhash: BlockHash::from_str(
                "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb4",
            )
            .unwrap(),
            uncles: vec![],
            miner_pubkey: "020202020202020202020202020202020202020202020202020202020202020202"
                .parse::<CompressedPublicKey>()
                .unwrap(),
            merkle_root: None,
            bits: CompactTarget::from_consensus(0x207fffff),
            time: 1700000000,
        };

        let cloned = commitment.clone();
        let header = ShareHeader::from_commitment_and_header(
            commitment,
            bitcoin_header,
            bitcoin_header.merkle_root,
        );

        assert_eq!(header.prev_share_blockhash, cloned.prev_share_blockhash);
        assert_eq!(header.uncles, cloned.uncles);
        assert_eq!(header.miner_pubkey, cloned.miner_pubkey);
        assert_eq!(header.merkle_root, bitcoin_header.merkle_root);
        assert_eq!(header.bitcoin_header, bitcoin_header);
        assert_eq!(header.bits, cloned.bits);
        assert_eq!(header.time, cloned.time);

        let hashed = cloned.hash();
        assert_ne!(hashed, bitcoin::hashes::sha256::Hash::all_zeros());
    }

    #[test]
    fn test_share_block_encode_decode_share_transaction_correctly() {
        // Build a share block with transactions
        let original = TestShareBlockBuilder::new()
            .prev_share_blockhash(
                "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb4".to_string(),
            )
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();

        // Verify we have share transactions
        assert!(!original.transactions.is_empty());
        assert!(original.transactions[0].is_coinbase());

        // Encode to bytes
        let encoded = serialize(&original);

        // Decode back
        let decoded: ShareBlock = deserialize(&encoded).expect("Failed to decode ShareBlock");

        // Verify share transactions match (comparing inner Transaction)
        for (orig_tx, decoded_tx) in original
            .transactions
            .iter()
            .zip(decoded.transactions.iter())
        {
            assert_eq!(orig_tx.compute_txid(), decoded_tx.compute_txid());
            assert_eq!(orig_tx.0, decoded_tx.0);
        }
    }
}
