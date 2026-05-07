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

pub mod share_transaction;
pub mod short_ids;

use super::transactions;
use crate::shares::coinbaseaux_flags::CoinbaseAuxFlags;
use crate::shares::extranonce::Extranonce;
use crate::shares::genesis;
use crate::shares::share_commitment::ShareCommitment;
use crate::shares::witness_commitment::WitnessCommitment;
use bitcoin::consensus::encode::Error::ParseFailed;
use bitcoin::{
    Address, BlockHash, CompactTarget, CompressedPublicKey, Target, TxMerkleNode, Txid, VarInt,
    block::Header,
    consensus::{Decodable, Encodable},
    hashes::Hash,
};
use core::mem;
use serde::{Deserialize, Serialize};
pub use share_transaction::ShareTransaction;
use std::error::Error;

/// The maximum target a share needs to have to be a valid share.
pub const MAX_POOL_TARGET: u32 = 0x1b384bd7;

/// The cumulative chain work multipler. We need at least as much work
/// on the cummulative chain as derived from MAX_POOL_TARGET times this constant.
pub const MIN_CUMULATIVE_CHAIN_WORK_MULTIPLIER: u64 = 1;

/// Header for the share chain block.
///
/// Excludes bitcoin compact block and share chain transactions.
/// Includes the bitcoin block hash for the bitcoin compact block instead.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ShareHeader {
    /// The hash of the prev share block, will be None for genesis block
    pub prev_share_blockhash: BlockHash,
    /// The uncles of the share
    pub uncles: Vec<BlockHash>,
    /// Bitcoin address identifying the miner
    #[serde(with = "crate::shares::address_serde")]
    pub miner_bitcoin_address: Address,
    /// Share block transactions merkle root - from blocktemplate
    pub merkle_root: TxMerkleNode,
    /// Bitcoin header the share is found for
    pub bitcoin_header: Header,
    /// Share chain difficult as compact target
    pub bits: CompactTarget,
    /// Timestamp for the share, as set by the miner
    pub time: u32,
    /// Donation address for developers
    #[serde(default, with = "crate::shares::option_address_serde")]
    pub donation_address: Option<Address>,
    /// Donation in basis points
    #[serde(default)]
    pub donation: Option<u16>,
    /// Fee address for the pool operator
    #[serde(default, with = "crate::shares::option_address_serde")]
    pub fee_address: Option<Address>,
    /// Fee in basis points
    #[serde(default)]
    pub fee: Option<u16>,
    /// Total bitcoin coinbase value - from blocktemplate
    pub coinbase_value: u64,
    /// coinbaseaux flags as decoded bytes - from blocktemplate, only the "flag" key
    #[serde(default)]
    pub coinbaseaux_flags: Option<CoinbaseAuxFlags>,
    /// BIP141 witness commitment - from blocktemplate
    #[serde(default)]
    pub witness_commitment: Option<WitnessCommitment>,
    /// Next bitcoin block height - from blocktemplate
    #[serde(default)]
    pub bitcoin_height: u64,
    /// Nanosecond timestamp embedded in the coinbase scriptSig
    #[serde(default)]
    pub coinbase_nsecs: u64,
    /// Combined extranonce (enonce1 || enonce2) from the stratum submission
    #[serde(default)]
    pub extranonce: Extranonce,
}

/// Encode an optional address as a bool flag followed by the address string when present.
fn encode_optional_address_string<W: bitcoin::io::Write + ?Sized>(
    address: &Option<Address>,
    writer: &mut W,
) -> Result<usize, bitcoin::io::Error> {
    let mut len = 0;
    match address {
        Some(addr) => {
            len += true.consensus_encode(writer)?;
            len += addr.to_string().consensus_encode(writer)?;
        }
        None => {
            len += false.consensus_encode(writer)?;
        }
    }
    Ok(len)
}

/// Decode an optional address from a bool flag followed by the address string.
fn decode_optional_address<R: bitcoin::io::Read + ?Sized>(
    reader: &mut R,
) -> Result<Option<Address>, bitcoin::consensus::encode::Error> {
    let has_address = bool::consensus_decode(reader)?;
    if has_address {
        let addr_str = String::consensus_decode(reader)?;
        let address = addr_str
            .parse::<Address<_>>()
            .map_err(|_| ParseFailed("invalid bitcoin address"))?
            .assume_checked();
        Ok(Some(address))
    } else {
        Ok(None)
    }
}

impl ShareHeader {
    /// Get the work defined by the bits field.
    pub(crate) fn get_work(&self) -> bitcoin::Work {
        Target::from_compact(self.bits).to_work()
    }

    /// Get the share chain difficulty as u128 from the bits field.
    ///
    /// Uses the network's max attainable target to compute the integer
    /// difficulty ratio (max_target / target).
    pub(crate) fn get_difficulty(&self, network: bitcoin::Network) -> u128 {
        Target::from_compact(self.bits).difficulty(network)
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
        coinbaseaux_flags: Option<CoinbaseAuxFlags>,
        witness_commitment: Option<WitnessCommitment>,
        height: u64,
        coinbase_nsecs: u64,
        extranonce: Extranonce,
    ) -> Self {
        Self {
            prev_share_blockhash: commitment.prev_share_blockhash,
            uncles: commitment.uncles,
            miner_bitcoin_address: commitment.miner_bitcoin_address,
            merkle_root: share_chain_merkle_root,
            bitcoin_header,
            bits: commitment.bits,
            time: commitment.time,
            donation_address: commitment.donation_address,
            donation: commitment.donation,
            fee_address: commitment.fee_address,
            fee: commitment.fee,
            coinbase_value: commitment.coinbase_value,
            coinbaseaux_flags,
            witness_commitment,
            bitcoin_height: height,
            coinbase_nsecs,
            extranonce,
        }
    }

    /// Block hash for the share header
    pub fn block_hash(&self) -> BlockHash {
        let mut engine = BlockHash::engine();
        self.consensus_encode(&mut engine)
            .expect("engines don't error");
        BlockHash::from_engine(engine)
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
        let addr_str = self.miner_bitcoin_address.to_string();
        len += addr_str.consensus_encode(w)?;
        len += self.merkle_root.consensus_encode(w)?;
        len += self.bitcoin_header.consensus_encode(w)?;
        len += self.bits.consensus_encode(w)?;
        len += self.time.consensus_encode(w)?;
        len += encode_optional_address_string(&self.donation_address, w)?;
        len += self.donation.unwrap_or(0).consensus_encode(w)?;
        len += encode_optional_address_string(&self.fee_address, w)?;
        len += self.fee.unwrap_or(0).consensus_encode(w)?;
        len += self.coinbase_value.consensus_encode(w)?;
        match &self.coinbaseaux_flags {
            Some(flags) => {
                len += true.consensus_encode(w)?;
                len += flags.consensus_encode(w)?;
            }
            None => len += false.consensus_encode(w)?,
        }
        match &self.witness_commitment {
            Some(commitment) => {
                len += true.consensus_encode(w)?;
                len += commitment.consensus_encode(w)?;
            }
            None => len += false.consensus_encode(w)?,
        }
        len += self.bitcoin_height.consensus_encode(w)?;
        len += self.coinbase_nsecs.consensus_encode(w)?;
        len += self.extranonce.consensus_encode(w)?;
        Ok(len)
    }
}

impl Decodable for ShareHeader {
    #[inline]
    fn consensus_decode<R: bitcoin::io::Read + ?Sized>(
        r: &mut R,
    ) -> Result<Self, bitcoin::consensus::encode::Error> {
        let prev_share_blockhash = BlockHash::consensus_decode(r)?;
        let uncles = Vec::<BlockHash>::consensus_decode(r)?;
        let addr_str = String::consensus_decode(r)?;
        let btcaddress = addr_str
            .parse::<Address<_>>()
            .map_err(|_| ParseFailed("invalid bitcoin address"))?
            .assume_checked();
        let merkle_root = TxMerkleNode::consensus_decode(r)?;
        let bitcoin_header = Header::consensus_decode(r)?;
        let bits = CompactTarget::consensus_decode(r)?;
        let time = u32::consensus_decode(r)?;
        let donation_address = decode_optional_address(r)?;
        let donation_raw = u16::consensus_decode(r)?;
        let donation = if donation_raw > 0 {
            Some(donation_raw)
        } else {
            None
        };
        let fee_address = decode_optional_address(r)?;
        let fee_raw = u16::consensus_decode(r)?;
        let fee = if fee_raw > 0 { Some(fee_raw) } else { None };

        let coinbase_value = u64::consensus_decode(r)?;
        let coinbaseaux_flags = if bool::consensus_decode(r)? {
            Some(CoinbaseAuxFlags::consensus_decode(r)?)
        } else {
            None
        };
        let witness_commitment = if bool::consensus_decode(r)? {
            Some(WitnessCommitment::consensus_decode(r)?)
        } else {
            None
        };
        let bitcoin_height = u64::consensus_decode(r)?;
        let coinbase_nsecs = u64::consensus_decode(r)?;
        let extranonce = Extranonce::consensus_decode(r)?;

        Ok(ShareHeader {
            prev_share_blockhash,
            uncles,
            miner_bitcoin_address: btcaddress,
            merkle_root,
            bitcoin_header,
            bits,
            time,
            donation_address,
            donation,
            fee_address,
            fee,
            coinbase_value,
            coinbaseaux_flags,
            witness_commitment,
            bitcoin_height,
            coinbase_nsecs,
            extranonce,
        })
    }
}

/// Captures a block on the share chain.
///
/// This captures the share chain header and the list of transactions
/// for the share chain, as well as bitcoin compact block.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ShareBlock {
    /// Header for the block
    #[serde(flatten)]
    pub header: ShareHeader,
    /// Share chain transactions - including the coinbase for the share.
    pub transactions: Vec<ShareTransaction>,
    /// Merkle path (branches) from coinbase position to the bitcoin
    /// merkle root. Used by validators to verify the bitcoin header's
    /// merkle_root matches the reconstructed coinbase.
    #[serde(default)]
    pub template_merkle_branches: Vec<TxMerkleNode>,
}

impl ShareBlock {
    /// Get difficulty for share header with given bitcoin network
    pub fn get_difficulty(&self, network: bitcoin::Network) -> u128 {
        self.header.bitcoin_header.difficulty(network)
    }

    /// Compute and return the block hash for this share block
    pub fn block_hash(&self) -> BlockHash {
        self.header.block_hash()
    }

    /// Build a genesis share block for a given network
    /// The bitcoin blockhash is hardcoded, so are the coinbase, nonce2, nonce, ntime, diff
    /// The workinfoid and clientid are 0 for genesis block on all networks
    pub fn build_genesis_for_network(
        network: bitcoin::Network,
    ) -> Result<Self, Box<dyn Error + Send + Sync>> {
        tracing::debug!("USING NETWORK {network}");
        assert!(
            network == bitcoin::Network::Signet
                || network == bitcoin::Network::Bitcoin
                || network == bitcoin::Network::Testnet4,
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
    fn build_genesis(
        genesis_data: &genesis::GenesisData,
        network: bitcoin::Network,
    ) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let public_key = genesis_data
            .public_key
            .parse::<CompressedPublicKey>()
            .unwrap();
        let btcaddress = Address::p2wpkh(&public_key, network);
        let coinbase =
            transactions::coinbase::build_sharechain_coinbase_transaction(&btcaddress, &[]);
        let coinbase_value = coinbase
            .output
            .iter()
            .fold(0, |memo, out| memo + out.value.to_sat());

        let transactions = vec![ShareTransaction(coinbase)];
        let merkle_root: TxMerkleNode =
            bitcoin::merkle_tree::calculate_root(transactions.iter().map(|tx| tx.compute_txid()))
                .unwrap()
                .into();

        let block_hex = hex::decode(genesis_data.bitcoin_block_hex).unwrap();
        // panic here, as if the genesis block is bad, we bail at the start of the process
        let bitcoin_block: bitcoin::Block = match bitcoin::consensus::deserialize(&block_hex) {
            Ok(block) => block,
            Err(e) => {
                tracing::info!("Failed to deserialize genesis block: {e}");
                return Err("Invalid genesis block data".into());
            }
        };

        let header = ShareHeader {
            prev_share_blockhash: BlockHash::all_zeros(),
            uncles: vec![],
            miner_bitcoin_address: btcaddress,
            bitcoin_header: bitcoin_block.header,
            merkle_root,
            time: genesis_data.timestamp,
            bits: CompactTarget::from_consensus(0x1b4188f5),
            donation_address: None,
            donation: None,
            fee_address: None,
            fee: None,
            coinbase_value,
            coinbaseaux_flags: None,
            witness_commitment: None,
            bitcoin_height: genesis_data.bitcoin_height,
            coinbase_nsecs: 0,
            extranonce: Extranonce::default(),
        };
        Ok(Self {
            header,
            transactions,
            template_merkle_branches: vec![],
        })
    }
}

/// Encode ShareBlock using rust-bitcoin Encodable support
///
/// We have a new type ShareTransaction and have to encode a vector of
/// `transactions` manually.
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
        // Encode template merkle path
        len += VarInt(self.template_merkle_branches.len() as u64).consensus_encode(w)?;
        for node in &self.template_merkle_branches {
            len += node.consensus_encode(w)?;
        }
        Ok(len)
    }
}

/// Decode ShareBlock using rust-bitcoin.
///
/// See comment on Encodable for handling `transactions`.
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
        // Decode template merkle path
        let path_count = VarInt::consensus_decode(r)?.0 as usize;
        let max_path_capacity = 32; // merkle path depth is at most ~30 for any realistic block
        if path_count > max_path_capacity {
            return Err(ParseFailed("template merkle path too long"));
        }
        let mut template_merkle_branches = Vec::with_capacity(path_count);
        for _ in 0..path_count {
            template_merkle_branches.push(TxMerkleNode::consensus_decode(r)?);
        }
        Ok(ShareBlock {
            header,
            transactions,
            template_merkle_branches,
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

/// A newtype for a vector of merkle branch nodes.
/// Provides Encodable/Decodable for storing in RocksDB.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleBranches(pub Vec<TxMerkleNode>);

impl Encodable for MerkleBranches {
    #[inline]
    fn consensus_encode<W: bitcoin::io::Write + ?Sized>(
        &self,
        w: &mut W,
    ) -> Result<usize, bitcoin::io::Error> {
        let mut len = 0;
        len += VarInt(self.0.len() as u64).consensus_encode(w)?;
        for node in self.0.iter() {
            len += node.consensus_encode(w)?;
        }
        Ok(len)
    }
}

impl Decodable for MerkleBranches {
    #[inline]
    fn consensus_decode_from_finite_reader<R: bitcoin::io::Read + ?Sized>(
        r: &mut R,
    ) -> Result<Self, bitcoin::consensus::encode::Error> {
        let count = VarInt::consensus_decode_from_finite_reader(r)?.0 as usize;
        // Merkle path depth is at most ~30 for any realistic block
        let max_capacity = 32;
        if count > max_capacity {
            return Err(bitcoin::consensus::encode::Error::ParseFailed(
                "template merkle branches too long",
            ));
        }
        let mut branches = Vec::with_capacity(count);
        for _ in 0..count {
            branches.push(TxMerkleNode::consensus_decode_from_finite_reader(r)?);
        }
        Ok(MerkleBranches(branches))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounting::OutputPair;
    use crate::accounting::payout::payout_distribution::{
        append_proportional_distribution, include_address_and_cut,
    };
    use crate::shares::share_commitment::ShareCommitment;
    use crate::stratum::work::coinbase::build_bitcoin_coinbase_transaction;
    use crate::stratum::work::gbt::compute_merkle_root_from_branches;
    use crate::test_utils::TestShareBlockBuilder;
    use bitcoin::consensus::{deserialize, serialize};
    use bitcoin::script::PushBytesBuf;
    use bitcoin::transaction::Version;
    use std::collections::HashMap;
    use std::str::FromStr;

    #[test]
    fn test_build_genesis_share_header() {
        let share = ShareBlock::build_genesis_for_network(bitcoin::Network::Signet).unwrap();

        assert!(share.header.uncles.is_empty());
        // Verify the genesis address is derived from the known pubkey
        let expected_pubkey = "02ac493f2130ca56cb5c3a559860cef9a84f90b5a85dfe4ec6e6067eeee17f4d2d"
            .parse::<CompressedPublicKey>()
            .unwrap();
        let expected_address = Address::p2wpkh(&expected_pubkey, bitcoin::Network::Signet);
        assert_eq!(share.header.miner_bitcoin_address, expected_address);
        assert_eq!(share.transactions.len(), 1);
        assert!(share.transactions[0].is_coinbase());
        // payout output + BIP141 witness commitment output
        assert_eq!(share.transactions[0].output.len(), 2);
        assert_eq!(share.transactions[0].input.len(), 1);

        let output = &share.transactions[0].output[0];
        assert_eq!(output.value.to_sat(), 100_000_000);

        assert_eq!(output.script_pubkey, expected_address.script_pubkey());
        assert_eq!(
            share.header.bitcoin_header.block_hash().to_string(),
            "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6"
        );
    }

    #[test]
    fn test_share_block_new_includes_coinbase_transaction() {
        let share_block = TestShareBlockBuilder::new().build();

        // Verify the coinbase transaction exists and has expected properties.
        // The share coinbase has two outputs: the payout and the BIP141
        // witness commitment.
        assert!(share_block.transactions[0].is_coinbase());
        assert_eq!(share_block.transactions[0].output.len(), 2);
        assert_eq!(share_block.transactions[0].input.len(), 1);

        let output = &share_block.transactions[0].output[0];
        assert_eq!(output.value.to_sat(), 100_000_000);

        // Verify the output script matches the builder's default address
        assert_eq!(
            output.script_pubkey,
            share_block.header.miner_bitcoin_address.script_pubkey()
        );
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
    fn test_from_commitment_and_header() {
        let bitcoin_header = TestShareBlockBuilder::new().build().header.bitcoin_header;
        let pubkey = "020202020202020202020202020202020202020202020202020202020202020202"
            .parse::<CompressedPublicKey>()
            .unwrap();
        let btcaddress = Address::p2wpkh(&pubkey, bitcoin::Network::Signet);

        let commitment = ShareCommitment {
            prev_share_blockhash: BlockHash::from_str(
                "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb4",
            )
            .unwrap(),
            uncles: vec![],
            miner_bitcoin_address: btcaddress,
            bits: CompactTarget::from_consensus(0x1b4188f5),
            time: 1700000000,
            donation_address: None,
            donation: None,
            fee_address: None,
            fee: None,
            coinbase_value: 100_000_000,
        };

        let cloned = commitment.clone();
        let header = ShareHeader::from_commitment_and_header(
            commitment,
            bitcoin_header,
            bitcoin_header.merkle_root,
            None,
            None,
            1,
            0,
            Extranonce::default(),
        );

        assert_eq!(header.prev_share_blockhash, cloned.prev_share_blockhash);
        assert_eq!(header.uncles, cloned.uncles);
        assert_eq!(header.miner_bitcoin_address, cloned.miner_bitcoin_address);
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

    #[test]
    fn test_fixture_coinbase_reconstruction_matches_bitcoin_merkle_root() {
        let fixture_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../p2poolv2_tests/test_data/share_sync/share_blocks.json");
        let json_string =
            std::fs::read_to_string(&fixture_path).expect("Failed to read share_blocks fixture");
        let blocks: Vec<ShareBlock> =
            serde_json::from_str(&json_string).expect("Failed to parse share_blocks fixture");

        let pool_signature = b"P2Poolv2";

        let network = bitcoin::Network::Signet;
        let difficulty_scale: u128 = 10;

        // Build PPLNS distribution matching the production PplnsWindow logic.
        // The threshold uses the bitcoin header difficulty (from the template),
        // while each share contributes its share chain difficulty (from header.bits).
        for (index, block) in blocks.iter().enumerate().skip(1) {
            let header = &block.header;
            let bitcoin_difficulty = header.bitcoin_header.difficulty(network);
            let scaled_threshold = bitcoin_difficulty.saturating_mul(difficulty_scale);

            let mut address_difficulty_map: HashMap<bitcoin::Address, u128> =
                HashMap::with_capacity(4);
            let mut accumulated_difficulty: u128 = 0;
            for prior_index in (0..index).rev() {
                let prior_header = &blocks[prior_index].header;
                let share_difficulty = prior_header.get_difficulty(network);
                let scaled_contribution = share_difficulty.saturating_mul(difficulty_scale);
                *address_difficulty_map
                    .entry(prior_header.miner_bitcoin_address.clone())
                    .or_insert(0) += scaled_contribution;
                accumulated_difficulty = accumulated_difficulty.saturating_add(scaled_contribution);
                if accumulated_difficulty >= scaled_threshold {
                    break;
                }
            }

            // Build outputs the same way the validator does
            let mut outputs = Vec::with_capacity(address_difficulty_map.len() + 2);
            let remaining_after_donation = include_address_and_cut(
                &mut outputs,
                bitcoin::Amount::from_sat(header.coinbase_value),
                &header.donation_address,
                header.donation,
            );
            let remaining_after_fees = include_address_and_cut(
                &mut outputs,
                remaining_after_donation,
                &header.fee_address,
                header.fee,
            );
            append_proportional_distribution(
                &address_difficulty_map,
                remaining_after_fees,
                &mut outputs,
            )
            .unwrap_or_else(|error| {
                panic!("Block {index}: failed to compute distribution: {error}")
            });

            let commitment_hash = ShareCommitment::from_share_header(header).hash();

            let flags = match &header.coinbaseaux_flags {
                Some(aux_flags) => aux_flags.to_push_bytes_buf(),
                None => PushBytesBuf::from(&[0u8]),
            };

            let reconstructed_coinbase = build_bitcoin_coinbase_transaction(
                Version::TWO,
                &outputs,
                header.bitcoin_height as i64,
                flags,
                header.witness_commitment.as_ref(),
                pool_signature,
                Some(commitment_hash),
                header.coinbase_nsecs,
                Some(header.extranonce.as_bytes()),
            )
            .unwrap_or_else(|error| panic!("Block {index}: failed to build coinbase: {error}"));

            let reconstructed_txid = reconstructed_coinbase.compute_txid();

            // With empty template_merkle_branches, the root equals the txid
            let recomputed_root = compute_merkle_root_from_branches(
                reconstructed_txid,
                &block.template_merkle_branches,
            );

            assert_eq!(
                recomputed_root, header.bitcoin_header.merkle_root,
                "Block {index}: reconstructed merkle root {} does not match bitcoin header merkle root {}",
                recomputed_root, header.bitcoin_header.merkle_root
            );
        }
    }
}
