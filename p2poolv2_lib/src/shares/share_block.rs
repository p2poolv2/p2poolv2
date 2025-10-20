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

use crate::shares::genesis;
use bitcoin::TxMerkleNode;
use bitcoin::hashes::Hash;
use bitcoin::{Block, BlockHash, PublicKey, Transaction, block::Header};
use serde::{Deserialize, Serialize};
use std::error::Error;

use super::transactions;

/// Header for the share chain block.
///
/// Exludes bitcoin compact block and share chain transactions.
/// Includes the bitcoin block hash for the bitcoin compact block instead.
///
/// TODO(pool2win): Add the donation and fee details used to build the coinbase.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct ShareHeader {
    /// The hash of the prev share block, will be None for genesis block
    pub prev_share_blockhash: BlockHash,
    /// The uncles of the share
    pub uncles: Vec<BlockHash>,
    /// Compressed pubkey identifying the miner
    pub miner_pubkey: PublicKey,
    /// Share block transactions merkle root
    pub merkle_root: TxMerkleNode,
    /// Bitcoin header the share is found for
    pub bitcoin_header: Header,
}

impl ShareHeader {
    /// Block hash for the share header
    pub fn block_hash(&self) -> BlockHash {
        let mut serialized = Vec::new();
        ciborium::ser::into_writer(&self, &mut serialized).unwrap();
        bitcoin::hashes::Hash::hash(&serialized)
    }

    /// Serialize the message to CBOR bytes
    pub fn cbor_serialize(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut buf = Vec::new();
        if let Err(e) = ciborium::ser::into_writer(&self, &mut buf) {
            return Err(e.into());
        }
        Ok(buf)
    }

    /// Deserialize a message from CBOR bytes
    pub fn cbor_deserialize(bytes: &[u8]) -> Result<Self, Box<dyn Error + Send + Sync>> {
        match ciborium::de::from_reader(bytes) {
            Ok(msg) => Ok(msg),
            Err(e) => Err(e.into()),
        }
    }
}

/// Captures a block on the share chain.
///
/// This captures the share chain header and the list of transactions
/// for the share chain, as well as bitcoin compact block.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct ShareBlock {
    /// Header for the block
    pub header: ShareHeader,
    /// Any share chain transactions to be included in the share block. We use rust-bitcoin Transactions.
    pub transactions: Vec<Transaction>,
    // /// ShortIds and nonce for the Bitcoin block. Header is already included in ShareHeader and we don't do prefilled transactions
    // pub bitcoin_shortids: ShortIdsAndNonce,
}

impl ShareBlock {
    /// Get difficulty for share header with given bitcoin network
    pub fn get_difficulty(&self, network: bitcoin::Network) -> u128 {
        self.header.bitcoin_header.difficulty(network)
    }

    /// Serialize the message to CBOR bytes
    pub fn cbor_serialize(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut buf = Vec::new();
        if let Err(e) = ciborium::ser::into_writer(&self, &mut buf) {
            return Err(e.into());
        }
        Ok(buf)
    }

    /// Deserialize a message from CBOR bytes
    pub fn cbor_deserialize(bytes: &[u8]) -> Result<Self, Box<dyn Error + Send + Sync>> {
        match ciborium::de::from_reader(bytes) {
            Ok(msg) => Ok(msg),
            Err(e) => Err(e.into()),
        }
    }

    pub fn genesis(_genesis_data: &genesis::GenesisData, public_key: PublicKey) -> Self {
        // TODO: Replace placeholder share with real data from pool
        let placeholder_block_hex = "00604d243d0b394c6c8d334d711ed3194ba3aa1f0e98673d17ede5f9f018c80000000000d0d7c1f59a8d08fed3cb59037fac64cabc248223ccb47ab35746ef14bb9abfe17be9ec684406021d3603418501020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff25020e400100047be9ec6804e82c6e030c536c314d110000000036cc3f085032506f6f6c7632ffffffff0440787d0100000000160014274466e754a1c12d0a2d2cc34ceb70d8e017053ae03fee0500000000160014274466e754a1c12d0a2d2cc34ceb70d8e017053ae0399a2201000000160014274466e754a1c12d0a2d2cc34ceb70d8e017053a0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000";
        let block: Block =
            bitcoin::consensus::deserialize(placeholder_block_hex.as_bytes()).unwrap();
        let header = ShareHeader {
            prev_share_blockhash: BlockHash::all_zeros(),
            uncles: vec![],
            miner_pubkey: public_key,
            merkle_root: TxMerkleNode::all_zeros(),
            bitcoin_header: block.header,
        };
        Self {
            header,
            transactions: vec![],
            // bitcoin_compact_block: compact_block::create_compact_block_from_share(&block),
        }
    }

    /// Build a new ShareBlock from the found bitcoin block and share chain metadata
    ///
    /// Share chain metadata includes previous block hash, uncles and
    /// transactions included in the share chain block.
    ///
    /// Miner pub key identifies the miner that found the share and is used to build the coinbase for the share block.
    pub fn new(
        bitcoin_block_header: Header,
        prev_share_blockhash: BlockHash,
        uncles: &[BlockHash],
        miner_pubkey: PublicKey,
        transactions: Vec<Transaction>,
        network: bitcoin::Network,
    ) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let coinbase = transactions::coinbase::create_coinbase_transaction(&miner_pubkey, network);
        let mut all_transactions = vec![coinbase];
        all_transactions.extend(transactions);
        let merkle_root = match bitcoin::merkle_tree::calculate_root(
            all_transactions.iter().map(Transaction::compute_txid),
        ) {
            Some(root) => root.into(),
            None => return Err("Failed to calculate merkle root for share block".into()),
        };

        let header = ShareHeader {
            prev_share_blockhash,
            uncles: uncles.to_vec(),
            miner_pubkey,
            bitcoin_header: bitcoin_block_header,
            merkle_root,
        };
        Ok(Self {
            header,
            transactions: all_transactions,
            // bitcoin_compact_block: compact_block::create_compact_block_from_share(&block),
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
        let public_key = genesis_data.public_key.parse::<PublicKey>().unwrap();
        let coinbase_tx = transactions::coinbase::create_coinbase_transaction(&public_key, network);
        let transactions = vec![coinbase_tx];
        let merkle_root: TxMerkleNode = bitcoin::merkle_tree::calculate_root(
            transactions.iter().map(Transaction::compute_txid),
        )
        .unwrap()
        .into();
        let block_hex = hex::decode(genesis_data.bitcoin_block_hex).unwrap();
        // panic here, as if the genesis block is bad, we bail at the start of the process
        let block: Block = match bitcoin::consensus::deserialize(&block_hex) {
            Ok(b) => b,
            Err(e) => {
                println!("Failed to deserialize genesis block: {e}");
                panic!("Invalid genesis block data");
            }
        };
        let header = ShareHeader {
            prev_share_blockhash: BlockHash::all_zeros(),
            uncles: vec![],
            miner_pubkey: public_key,
            bitcoin_header: block.header,
            merkle_root,
        };
        Self {
            header,
            transactions,
            // bitcoin_compact_block: compact_block::create_compact_block_from_share(&block),
        }
    }
}

/// A variant of ShareBlock used for storage that excludes transactions
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct StorageShareBlock {
    /// The header of the share block
    pub header: ShareHeader,
    /// List of txids. Full transactions are stored separately in transactions cf.
    pub txids: Vec<bitcoin::Txid>,
}

impl From<ShareBlock> for StorageShareBlock {
    fn from(block: ShareBlock) -> Self {
        Self {
            header: block.header,
            txids: block
                .transactions
                .iter()
                .map(|tx| tx.compute_txid())
                .collect(),
        }
    }
}

#[allow(dead_code)]
impl StorageShareBlock {
    /// Convert back to ShareBlock with empty transactions and block
    pub fn into_share_block(self) -> ShareBlock {
        ShareBlock {
            header: self.header,
            // TODO: Fetch transactions using txid vector
            transactions: vec![],
        }
    }

    /// Convert back to ShareBlock with provided transactions
    pub fn into_share_block_with_transactions(self, transactions: Vec<Transaction>) -> ShareBlock {
        ShareBlock {
            header: self.header,
            transactions,
        }
    }

    /// Serialize the message to CBOR bytes
    pub fn cbor_serialize(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut buf = Vec::new();
        if let Err(e) = ciborium::ser::into_writer(&self, &mut buf) {
            return Err(e.into());
        }
        Ok(buf)
    }

    /// Deserialize a message from CBOR bytes
    pub fn cbor_deserialize(bytes: &[u8]) -> Result<Self, Box<dyn Error>> {
        match ciborium::de::from_reader(bytes) {
            Ok(msg) => Ok(msg),
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TestShareBlockBuilder;
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
        assert_eq!(output.value.to_sat(), 1);

        let expected_address = bitcoin::Address::p2pkh(
            "02ac493f2130ca56cb5c3a559860cef9a84f90b5a85dfe4ec6e6067eeee17f4d2d"
                .parse::<PublicKey>()
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
    fn test_share_serialization() {
        let share = TestShareBlockBuilder::new()
            .prev_share_blockhash(
                "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb4".to_string(),
            )
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .diff(1)
            .build();

        let serialized = share.cbor_serialize().unwrap();
        let deserialized = ShareBlock::cbor_deserialize(&serialized).unwrap();

        assert_eq!(
            share.header.prev_share_blockhash,
            deserialized.header.prev_share_blockhash
        );
        assert_eq!(share.header.uncles, deserialized.header.uncles);
        assert_eq!(share.header.miner_pubkey, deserialized.header.miner_pubkey);
        assert_eq!(share.transactions, deserialized.transactions);
    }

    #[test]
    fn test_share_block_new_includes_coinbase_transaction() {
        // Create a test public key
        let pubkey = "020202020202020202020202020202020202020202020202020202020202020202"
            .parse::<PublicKey>()
            .unwrap();

        let share_block = TestShareBlockBuilder::new().build();

        // Verify the coinbase transaction exists and has expected properties
        assert!(share_block.transactions[0].is_coinbase());
        assert_eq!(share_block.transactions[0].output.len(), 1);
        assert_eq!(share_block.transactions[0].input.len(), 1);

        // Verify the output is a P2PKH to the miner's public key
        let output = &share_block.transactions[0].output[0];
        assert_eq!(output.value.to_sat(), 1);

        // Verify the output script is P2PKH for the miner's pubkey
        let expected_address = bitcoin::Address::p2pkh(pubkey, bitcoin::Network::Regtest);
        assert_eq!(output.script_pubkey, expected_address.script_pubkey());
    }

    #[test]
    fn test_storage_share_block_conversion() {
        let share = TestShareBlockBuilder::new()
            .prev_share_blockhash(
                "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb4".into(),
            )
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .diff(1)
            .build();

        // Test conversion to StorageShareBlock
        let storage_share: StorageShareBlock = share.clone().into();

        // Verify header and miner_share are preserved
        assert_eq!(storage_share.header, share.header);

        // Test conversion back to ShareBlock with empty transactions
        let recovered_share = storage_share.clone().into_share_block();
        assert_eq!(recovered_share.header, share.header);
        assert!(recovered_share.transactions.is_empty());

        // Test conversion back with original transactions
        let recovered_share =
            storage_share.into_share_block_with_transactions(share.transactions.clone());
        assert_eq!(recovered_share, share);
    }

    #[test]
    fn test_share_block_new() {
        // Create a bitcoin block header
        let bitcoin_header = TestShareBlockBuilder::new().build().header.bitcoin_header;

        // Create test data
        let prev_share_blockhash =
            BlockHash::from_str("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb4")
                .unwrap();
        let uncles = vec![
            BlockHash::from_str("00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6")
                .unwrap(),
        ];
        let miner_pubkey = "020202020202020202020202020202020202020202020202020202020202020202"
            .parse::<PublicKey>()
            .unwrap();
        let transactions = Vec::<Transaction>::new(); // No additional transactions
        let network = bitcoin::Network::Signet;

        // Create the share block
        let share_block = ShareBlock::new(
            bitcoin_header,
            prev_share_blockhash,
            &uncles,
            miner_pubkey,
            transactions,
            network,
        )
        .unwrap();

        // Verify basic properties
        assert_eq!(
            share_block.header.prev_share_blockhash,
            prev_share_blockhash
        );
        assert_eq!(share_block.header.uncles, uncles);
        assert_eq!(share_block.header.miner_pubkey, miner_pubkey);
        assert_eq!(share_block.header.bitcoin_header, bitcoin_header);

        // Verify transactions include coinbase
        assert_eq!(share_block.transactions.len(), 1);
        assert!(share_block.transactions[0].is_coinbase());

        // Verify merkle root is correctly calculated
        let expected_merkle_root = bitcoin::merkle_tree::calculate_root(
            share_block
                .transactions
                .iter()
                .map(Transaction::compute_txid),
        )
        .unwrap()
        .into();
        assert_eq!(share_block.header.merkle_root, expected_merkle_root);
    }
}
