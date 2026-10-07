// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

pub mod share_transaction;
pub mod short_ids;

use super::transactions;
use crate::address::Address as P2PoolAddress;
use crate::shares::coinbase_proof::{CoinbaseProof, MAX_COINBASE_MERKLE_BRANCH_LENGTH};
use crate::shares::genesis;
use crate::shares::share_commitment::ShareCommitment;
use crate::sim_overrides;
use bitcoin::consensus::encode::Error::ParseFailed;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{
    Address, BlockHash, CompactTarget, CompressedPublicKey, Target, Transaction, TxMerkleNode,
    Txid, VarInt, WitnessProgram,
    block::Header,
    consensus::{Decodable, Encodable},
    hashes::Hash,
};
use core::mem;
use p2poolv2_wallet::witness_program_codec;
use serde::{Deserialize, Serialize};
pub use share_transaction::{
    DuplicatePrevoutError, ShareTransaction, SpendingPrevouts, extract_spending_prevouts,
};
use std::error::Error;

/// The maximum target a share needs to have to be a valid share.
pub const MAX_POOL_TARGET: u32 = 0x1b384bd7;

/// The cumulative chain work multipler. We need at least as much work
/// on the cummulative chain as derived from MAX_POOL_TARGET times this constant.
pub const MIN_CUMULATIVE_CHAIN_WORK_MULTIPLIER: u64 = 1;

/// True when a blockhash is the terminal marker of a share's parent chain --
/// the all-zeros value the genesis share stores as its `prev_share_blockhash`
/// to mean "no parent". Walks up the parent chain stop here.
pub fn is_terminal_blockhash(blockhash: &BlockHash) -> bool {
    *blockhash == BlockHash::all_zeros()
}

/// Header for the share chain block.
///
/// Excludes bitcoin compact block and share chain transactions.
/// Includes the bitcoin block hash for the bitcoin compact block instead.
///
/// Every field is bound to the proof of work, because `block_hash` covers
/// every field: a field the proof of work did not fix could be changed to give
/// one proof of work many share hashes. Each field is the bitcoin header
/// itself, digested into the share commitment, fixed by the coinbase tail
/// (`bitcoin_height`, through the locktime), or the `coinbase_proof` whose
/// coinbase txid the bitcoin merkle root fixes. Data the proof of work fixes
/// but a header cannot check, such as the extranonce, lives in the bitcoin
/// coinbase carried by the `ShareBlock`.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ShareHeader {
    /// The hash of the prev share block, will be None for genesis block
    pub prev_share_blockhash: BlockHash,
    /// The uncles of the share
    pub uncles: Vec<BlockHash>,
    /// Bitcoin address identifying the miner, receiving the bitcoin payout
    #[serde(with = "crate::shares::address_serde")]
    pub miner_bitcoin_address: Address,
    /// Share chain miner address owning this share's coinbase output, stored
    /// as the witness program that address encodes. A different chain and a
    /// different key from `miner_bitcoin_address`.
    ///
    /// The witness program rather than the `Address` because an address also
    /// names a network, and the network is not consensus data: the chain knows
    /// which one it is from its own configuration, and a share from another
    /// chain fails on its parent hash and difficulty long before its miner
    /// address matters. Storing it would let one output be spelled four ways, and
    /// since `block_hash` covers every field, each spelling would be a
    /// distinct block carrying the same proof of work.
    #[serde(with = "p2poolv2_wallet::witness_program_codec::serde_hex")]
    pub miner_address: WitnessProgram,
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
    /// Next bitcoin block height - from blocktemplate
    #[serde(default)]
    pub bitcoin_height: u64,
    /// Midstate proof that this header's commitment ends the coinbase of
    /// `bitcoin_header`, checkable with the coinbase merkle branch alone.
    /// See `CoinbaseProof`.
    #[serde(default)]
    pub coinbase_proof: CoinbaseProof,
}

/// Network class an encoded address is rebuilt for: the part of an
/// `Address` its script does not carry. Segwit addresses carry an HRP and
/// legacy ones a network kind; these three classes cover both.
const ADDRESS_NETWORK_MAIN: u8 = 0;
const ADDRESS_NETWORK_TEST: u8 = 1;
const ADDRESS_NETWORK_REGTEST: u8 = 2;

/// Encode an address as its network class and script pubkey.
///
/// Shorter than the address string (a P2TR script is 34 bytes against 62
/// characters), and exact: decoding rebuilds the same `Address`.
pub(crate) fn encode_address<W: bitcoin::io::Write + ?Sized>(
    address: &Address,
    writer: &mut W,
) -> Result<usize, bitcoin::io::Error> {
    let network_class = if address
        .as_unchecked()
        .is_valid_for_network(bitcoin::Network::Bitcoin)
    {
        ADDRESS_NETWORK_MAIN
    } else if address
        .as_unchecked()
        .is_valid_for_network(bitcoin::Network::Testnet)
    {
        ADDRESS_NETWORK_TEST
    } else {
        ADDRESS_NETWORK_REGTEST
    };
    let mut len = network_class.consensus_encode(writer)?;
    len += address.script_pubkey().consensus_encode(writer)?;
    Ok(len)
}

/// Decode an address written by `encode_address`.
fn decode_address<R: bitcoin::io::Read + ?Sized>(
    reader: &mut R,
) -> Result<Address, bitcoin::consensus::encode::Error> {
    let network = match u8::consensus_decode(reader)? {
        ADDRESS_NETWORK_MAIN => bitcoin::Network::Bitcoin,
        ADDRESS_NETWORK_TEST => bitcoin::Network::Testnet,
        ADDRESS_NETWORK_REGTEST => bitcoin::Network::Regtest,
        _ => return Err(ParseFailed("unknown address network class")),
    };
    let script = bitcoin::ScriptBuf::consensus_decode(reader)?;
    Address::from_script(&script, network).map_err(|_| ParseFailed("invalid address script"))
}

/// Encode an optional address as a bool flag followed by the address when present.
fn encode_optional_address<W: bitcoin::io::Write + ?Sized>(
    address: &Option<Address>,
    writer: &mut W,
) -> Result<usize, bitcoin::io::Error> {
    match address {
        Some(address) => Ok(true.consensus_encode(writer)? + encode_address(address, writer)?),
        None => false.consensus_encode(writer),
    }
}

/// Decode an optional address from a bool flag followed by the address.
fn decode_optional_address<R: bitcoin::io::Read + ?Sized>(
    reader: &mut R,
) -> Result<Option<Address>, bitcoin::consensus::encode::Error> {
    if bool::consensus_decode(reader)? {
        Ok(Some(decode_address(reader)?))
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
    /// bitcoin header. That happens at the receiving node, through
    /// `coinbase_proof`.
    pub(crate) fn from_commitment_and_header(
        commitment: ShareCommitment,
        bitcoin_header: Header,
        height: u64,
        coinbase_proof: CoinbaseProof,
    ) -> Self {
        Self {
            prev_share_blockhash: commitment.prev_share_blockhash,
            uncles: commitment.uncles,
            miner_bitcoin_address: commitment.miner_bitcoin_address,
            miner_address: commitment.miner_address,
            bitcoin_header,
            bits: commitment.bits,
            time: commitment.time,
            donation_address: commitment.donation_address,
            donation: commitment.donation,
            fee_address: commitment.fee_address,
            fee: commitment.fee,
            bitcoin_height: height,
            coinbase_proof,
        }
    }

    /// Block hash for the share header
    pub fn block_hash(&self) -> BlockHash {
        let mut engine = BlockHash::engine();
        self.consensus_encode(&mut engine)
            .expect("engines don't error");
        BlockHash::from_engine(engine)
    }

    /// True when this share's bitcoin header meets the bitcoin network target,
    /// i.e. the share found a bitcoin block.
    ///
    /// On the header rather than the block because the confirmed-block
    /// follow-up in the organise worker works from headers: the transactions
    /// say nothing about whether the PoW cleared the network target.
    pub fn meets_bitcoin_difficulty(&self) -> bool {
        Target::from_compact(self.bitcoin_header.bits).is_met_by(self.bitcoin_header.block_hash())
    }
}

impl ShareHeader {
    /// Encode the header, optionally leaving out `bitcoin_header.merkle_root`.
    ///
    /// The canonical encoding -- the block hash, the store, a `ShareBlock` --
    /// includes the root. A `ShareHeaderBatch` leaves it out where the
    /// header's coinbase proof and branch give it back: the receiver derives
    /// the root, and a header whose proof derives the wrong root fails its
    /// proof-of-work check.
    pub(crate) fn consensus_encode_with<W: bitcoin::io::Write + ?Sized>(
        &self,
        w: &mut W,
        include_bitcoin_merkle_root: bool,
    ) -> Result<usize, bitcoin::io::Error> {
        let mut len = 0;
        len += self.prev_share_blockhash.consensus_encode(w)?;
        len += self.uncles.consensus_encode(w)?;
        len += encode_address(&self.miner_bitcoin_address, w)?;
        len += witness_program_codec::consensus_encode(&self.miner_address, w)?;
        len += self.bitcoin_header.version.consensus_encode(w)?;
        len += self.bitcoin_header.prev_blockhash.consensus_encode(w)?;
        if include_bitcoin_merkle_root {
            len += self.bitcoin_header.merkle_root.consensus_encode(w)?;
        }
        len += self.bitcoin_header.time.consensus_encode(w)?;
        len += self.bitcoin_header.bits.consensus_encode(w)?;
        len += self.bitcoin_header.nonce.consensus_encode(w)?;
        len += self.bits.consensus_encode(w)?;
        len += self.time.consensus_encode(w)?;
        len += encode_optional_address(&self.donation_address, w)?;
        len += self.donation.unwrap_or(0).consensus_encode(w)?;
        len += encode_optional_address(&self.fee_address, w)?;
        len += self.fee.unwrap_or(0).consensus_encode(w)?;
        len += self.bitcoin_height.consensus_encode(w)?;
        len += self.coinbase_proof.consensus_encode(w)?;
        Ok(len)
    }

    /// Decode a header written by `consensus_encode_with`. Without the root,
    /// `bitcoin_header.merkle_root` is all zeros until the caller derives it.
    pub(crate) fn consensus_decode_with<R: bitcoin::io::Read + ?Sized>(
        r: &mut R,
        include_bitcoin_merkle_root: bool,
    ) -> Result<Self, bitcoin::consensus::encode::Error> {
        let prev_share_blockhash = BlockHash::consensus_decode(r)?;
        let uncles = Vec::<BlockHash>::consensus_decode(r)?;
        let miner_bitcoin_address = decode_address(r)?;
        let miner_address = witness_program_codec::consensus_decode(r)?;
        let bitcoin_version = bitcoin::block::Version::consensus_decode(r)?;
        let bitcoin_prev_blockhash = BlockHash::consensus_decode(r)?;
        let bitcoin_merkle_root = if include_bitcoin_merkle_root {
            TxMerkleNode::consensus_decode(r)?
        } else {
            TxMerkleNode::all_zeros()
        };
        let bitcoin_header = Header {
            version: bitcoin_version,
            prev_blockhash: bitcoin_prev_blockhash,
            merkle_root: bitcoin_merkle_root,
            time: u32::consensus_decode(r)?,
            bits: CompactTarget::consensus_decode(r)?,
            nonce: u32::consensus_decode(r)?,
        };
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

        let bitcoin_height = u64::consensus_decode(r)?;
        let coinbase_proof = CoinbaseProof::consensus_decode(r)?;

        Ok(ShareHeader {
            prev_share_blockhash,
            uncles,
            miner_bitcoin_address,
            miner_address,
            bitcoin_header,
            bits,
            time,
            donation_address,
            donation,
            fee_address,
            fee,
            bitcoin_height,
            coinbase_proof,
        })
    }
}

impl Encodable for ShareHeader {
    #[inline]
    fn consensus_encode<W: bitcoin::io::Write + ?Sized>(
        &self,
        w: &mut W,
    ) -> Result<usize, bitcoin::io::Error> {
        self.consensus_encode_with(w, true)
    }
}

impl Decodable for ShareHeader {
    #[inline]
    fn consensus_decode<R: bitcoin::io::Read + ?Sized>(
        r: &mut R,
    ) -> Result<Self, bitcoin::consensus::encode::Error> {
        Self::consensus_decode_with(r, true)
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
    /// The bitcoin coinbase the miner hashed: its scriptSig carries the aux
    /// flags, extranonce and nanosecond timestamp, and its outputs the payouts,
    /// the BIP141 witness commitment and the share commitment.
    ///
    /// Not part of the block hash. The proof of work fixes it instead: its
    /// txid must be the one the header's `coinbase_proof` gives, which the
    /// admission gate checks before the block is stored, so a copy with a
    /// different coinbase is a bad copy rather than another block.
    #[serde(default = "empty_bitcoin_coinbase")]
    pub bitcoin_coinbase: Transaction,
}

/// The bitcoin coinbase of a block written before `ShareBlock` carried one:
/// no inputs and no outputs, so it matches no proof and never validates.
pub(crate) fn empty_bitcoin_coinbase() -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: Vec::new(),
        output: Vec::new(),
    }
}

impl ShareBlock {
    /// Get difficulty for share header with given bitcoin network
    pub fn get_difficulty(&self, network: bitcoin::Network) -> u128 {
        self.header.bitcoin_header.difficulty(network)
    }

    /// True when this share's bitcoin header meets the bitcoin network
    /// target, i.e. the share found a bitcoin block. Detected from the share
    /// itself so it holds pool-wide (every node sees the share on the chain),
    /// not just for blocks found by locally connected miners.
    pub fn is_bitcoin_block(&self) -> bool {
        self.header.meets_bitcoin_difficulty()
    }

    /// Compute and return the block hash for this share block
    pub fn block_hash(&self) -> BlockHash {
        self.header.block_hash()
    }

    /// Merkle root over the block's transactions, coinbase first.
    ///
    /// Computed rather than carried on the header: the header binds the
    /// transactions through its proof's `share_witness_root` and the share
    /// coinbase it implies, so a stored root would add nothing the proof of
    /// work holds to. Returns `None` for a block with no transactions.
    pub fn merkle_root(&self) -> Option<TxMerkleNode> {
        bitcoin::merkle_tree::calculate_root(
            self.transactions
                .iter()
                .map(|transaction| transaction.compute_txid()),
        )
        .map(TxMerkleNode::from)
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
                || network == bitcoin::Network::Testnet4
                || network == bitcoin::Network::Regtest,
            "Network Testnet not yet supported"
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
        // Genesis is the one place deriving the share address from the bitcoin
        // key is right: this is a NUMS key nobody can spend on either chain.
        let secp = Secp256k1::verification_only();
        let miner_address = P2PoolAddress::from_internal_key(
            public_key.0.x_only_public_key().0,
            None,
            network,
            &secp,
        )?
        .witness_program();
        let block_hex = hex::decode(genesis_data.bitcoin_block_hex).unwrap();
        // panic here, as if the genesis block is bad, we bail at the start of the process
        let bitcoin_block: bitcoin::Block = match bitcoin::consensus::deserialize(&block_hex) {
            Ok(block) => block,
            Err(e) => {
                tracing::error!("Failed to deserialize genesis block: {e}");
                return Err("Invalid genesis block data".into());
            }
        };

        // The bitcoin block is deserialized before the coinbase is built,
        // because the share coinbase now carries its hash. Genesis is the one
        // share whose weak block is fixed data rather than mined.
        let coinbase = transactions::coinbase::build_sharechain_coinbase_transaction(
            &miner_address,
            bitcoin_block.header.block_hash(),
            &[],
        );
        let transactions = vec![ShareTransaction(coinbase)];

        let genesis_time = sim_overrides::genesis_timestamp(genesis_data);
        let genesis_bits = sim_overrides::anchor_target();

        let header = ShareHeader {
            prev_share_blockhash: BlockHash::all_zeros(),
            uncles: vec![],
            miner_bitcoin_address: btcaddress,
            miner_address,
            bitcoin_header: bitcoin_block.header,
            time: genesis_time,
            bits: genesis_bits,
            donation_address: None,
            donation: None,
            fee_address: None,
            fee: None,
            bitcoin_height: genesis_data.bitcoin_height,
            // The genesis coinbase predates the share chain and carries no
            // commitment. Genesis is built locally and never verified.
            coinbase_proof: CoinbaseProof::default(),
        };
        let bitcoin_coinbase = bitcoin_block
            .txdata
            .first()
            .cloned()
            .ok_or("Genesis bitcoin block has no coinbase")?;
        Ok(Self {
            header,
            transactions,
            template_merkle_branches: vec![],
            bitcoin_coinbase,
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
        len += self.bitcoin_coinbase.consensus_encode(w)?;
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
        if path_count > MAX_COINBASE_MERKLE_BRANCH_LENGTH {
            return Err(ParseFailed("template merkle path too long"));
        }
        let mut template_merkle_branches = Vec::with_capacity(path_count);
        for _ in 0..path_count {
            template_merkle_branches.push(TxMerkleNode::consensus_decode(r)?);
        }
        let bitcoin_coinbase = Transaction::consensus_decode(r)?;
        Ok(ShareBlock {
            header,
            transactions,
            template_merkle_branches,
            bitcoin_coinbase,
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
        if count > MAX_COINBASE_MERKLE_BRANCH_LENGTH {
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
    use crate::accounting::payout::payout_distribution::{
        append_proportional_distribution, include_address_and_cut,
    };
    use crate::shares::share_commitment::ShareCommitment;
    use crate::shares::transactions::coinbase::compute_witness_root;
    use crate::stratum::work::coinbase::{
        build_bitcoin_coinbase_transaction, parse_bitcoin_coinbase_fields,
    };
    use crate::stratum::work::gbt::compute_merkle_root_from_branches;
    use crate::test_utils::TestShareBlockBuilder;
    use crate::test_utils::make_test_share_program;
    use bitcoin::ScriptBuf;
    use bitcoin::consensus::{deserialize, serialize};
    use bitcoin::transaction::Version;
    use std::collections::HashMap;
    use std::str::FromStr;

    #[test]
    fn test_is_bitcoin_block() {
        // A default test share is not a mined bitcoin block: its bitcoin
        // header hash does not meet the network target.
        let share = TestShareBlockBuilder::new().build();
        assert!(!share.is_bitcoin_block());

        // The regtest genesis header meets its own (easy) target by
        // construction, so it reads as a found bitcoin block.
        let mut block_share = TestShareBlockBuilder::new().build();
        block_share.header.bitcoin_header =
            bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest).header;
        assert!(block_share.is_bitcoin_block());
    }

    #[test]
    fn test_build_genesis_share_header() {
        let share = ShareBlock::build_genesis_for_network(bitcoin::Network::Signet).unwrap();

        assert!(share.header.uncles.is_empty());
        // Verify the genesis address is derived from the known pubkey
        let expected_pubkey = "02ac493f2130ca56cb5c3a559860cef9a84f90b5a85dfe4ec6e6067eeee17f4d2d"
            .parse::<CompressedPublicKey>()
            .unwrap();
        let expected_bitcoin_address = Address::p2wpkh(&expected_pubkey, bitcoin::Network::Signet);
        assert_eq!(share.header.miner_bitcoin_address, expected_bitcoin_address);
        assert_eq!(share.transactions.len(), 1);
        assert!(share.transactions[0].is_coinbase());
        // payout output + BIP141 witness commitment output
        assert_eq!(share.transactions[0].output.len(), 2);
        assert_eq!(share.transactions[0].input.len(), 1);

        let output = &share.transactions[0].output[0];
        assert_eq!(output.value.to_sat(), 100_000_000);

        // The share coinbase pays the share chain miner address; the bitcoin address
        // is the payout identity on bitcoin and is not this output.
        assert_eq!(
            output.script_pubkey,
            ScriptBuf::new_witness_program(&share.header.miner_address)
        );
        assert_ne!(
            output.script_pubkey,
            expected_bitcoin_address.script_pubkey(),
            "the two chains must not share an output script"
        );
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

        // Verify the output script matches the builder's share chain address
        assert_eq!(
            output.script_pubkey,
            ScriptBuf::new_witness_program(&share_block.header.miner_address)
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

        // The merkle root is computed from the transactions, coinbase first.
        let expected_merkle_root: TxMerkleNode = bitcoin::merkle_tree::calculate_root(
            share_block.transactions.iter().map(|tx| tx.compute_txid()),
        )
        .unwrap()
        .into();
        assert_eq!(share_block.merkle_root(), Some(expected_merkle_root));
    }

    #[test]
    fn test_from_commitment_and_header() {
        let bitcoin_header = TestShareBlockBuilder::new().build().header.bitcoin_header;
        let pubkey = "020202020202020202020202020202020202020202020202020202020202020202"
            .parse::<CompressedPublicKey>()
            .unwrap();
        let btcaddress = Address::p2wpkh(&pubkey, bitcoin::Network::Signet);

        let share_address = make_test_share_program(1);
        let commitment = ShareCommitment {
            miner_address: share_address,
            share_witness_root: compute_witness_root(&[]),
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
        };

        let cloned = commitment.clone();
        let header = ShareHeader::from_commitment_and_header(
            commitment,
            bitcoin_header,
            1,
            CoinbaseProof::default(),
        );

        assert_eq!(header.prev_share_blockhash, cloned.prev_share_blockhash);
        assert_eq!(header.uncles, cloned.uncles);
        assert_eq!(header.miner_bitcoin_address, cloned.miner_bitcoin_address);
        assert_eq!(header.miner_address, cloned.miner_address);
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

    /// Addresses encode as a network class and script and decode to the same
    /// `Address`, so the header and its hash round-trip.
    #[test]
    fn test_share_header_round_trips_mainnet_segwit_address() {
        let mut header = TestShareBlockBuilder::new().build().header;
        header.miner_bitcoin_address =
            Address::from_str("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
                .unwrap()
                .assume_checked();
        let decoded: ShareHeader = deserialize(&serialize(&header)).unwrap();
        assert_eq!(decoded, header);
        assert_eq!(decoded.block_hash(), header.block_hash());
    }

    #[test]
    fn test_share_header_round_trips_testnet_segwit_address() {
        let mut header = TestShareBlockBuilder::new().build().header;
        header.miner_bitcoin_address =
            Address::from_str("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx")
                .unwrap()
                .assume_checked();
        let decoded: ShareHeader = deserialize(&serialize(&header)).unwrap();
        assert_eq!(decoded, header);
    }

    #[test]
    fn test_share_header_round_trips_regtest_segwit_address() {
        let mut header = TestShareBlockBuilder::new().build().header;
        header.miner_bitcoin_address = Address::p2wsh(&ScriptBuf::new(), bitcoin::Network::Regtest);
        let decoded: ShareHeader = deserialize(&serialize(&header)).unwrap();
        assert_eq!(decoded, header);
    }

    #[test]
    fn test_share_header_round_trips_mainnet_legacy_address() {
        let mut header = TestShareBlockBuilder::new().build().header;
        header.miner_bitcoin_address = Address::from_str("1HpRF3JgafxaqjhMEjLNbevpRVvAp15t3A")
            .unwrap()
            .assume_checked();
        let decoded: ShareHeader = deserialize(&serialize(&header)).unwrap();
        assert_eq!(decoded, header);
    }

    #[test]
    fn test_share_header_round_trips_donation_and_fee_addresses() {
        let mut header = TestShareBlockBuilder::new().build().header;
        header.donation_address = Some(
            Address::from_str("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx")
                .unwrap()
                .assume_checked(),
        );
        header.donation = Some(200);
        header.fee_address = Some(Address::p2wsh(&ScriptBuf::new(), bitcoin::Network::Regtest));
        header.fee = Some(100);
        let decoded: ShareHeader = deserialize(&serialize(&header)).unwrap();
        assert_eq!(decoded, header);
    }

    #[test]
    #[ignore = "share_sync fixtures were built before share headers dropped merkle_root, coinbase_value and the coinbase fields, and the commitment bound the share witness root; regenerate them"]
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
                block
                    .bitcoin_coinbase
                    .output
                    .iter()
                    .map(|output| output.value)
                    .sum(),
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

            let commitment_hash = ShareCommitment::from_share_block(block).hash();

            let fields = parse_bitcoin_coinbase_fields(&block.bitcoin_coinbase)
                .unwrap_or_else(|error| panic!("Block {index}: malformed coinbase: {error}"));

            let reconstructed_coinbase = build_bitcoin_coinbase_transaction(
                Version::TWO,
                &outputs,
                header.bitcoin_height as i64,
                fields.aux_flags,
                fields.witness_commitment.as_ref(),
                pool_signature,
                Some(commitment_hash),
                fields.nsecs,
                Some(&fields.extranonce),
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
