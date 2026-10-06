// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bitcoin blocks found by the pool, derived from the share chain.
//!
//! A share header whose bitcoin header meets the bitcoin network target
//! is a bitcoin block found by the pool. When such a share, or an uncle
//! of a share, is confirmed, the find is recorded in the FoundBlocks
//! column family in the same batch as the confirmation. Entries are
//! never deleted: the bitcoin block exists regardless of later share
//! chain reorgs, and whether it stayed on the bitcoin main chain is left
//! to block explorers.

use super::{ColumnFamily, Store, writer::StoreError};
use crate::shares::share_block::ShareHeader;
use bitcoin::BlockHash;
use bitcoin::consensus::encode::{self, Decodable, Encodable};

/// Size of the big endian bitcoin height prefix in a FoundBlocks key.
const HEIGHT_KEY_PREFIX_LENGTH: usize = 8;

/// A bitcoin block found by the pool.
///
/// The key in the FoundBlocks column family is the big endian bitcoin
/// height followed by the bitcoin blockhash, so iteration is ordered by
/// height and two finds at the same height do not collide. The value
/// carries the remaining fields.
#[derive(Debug, Clone, PartialEq)]
pub struct FoundBlock {
    /// Bitcoin height of the found block
    pub bitcoin_height: u64,
    /// Hash of the found bitcoin block
    pub bitcoin_blockhash: BlockHash,
    /// Hash of the share whose header carries the bitcoin block
    pub share_blockhash: BlockHash,
    /// Bitcoin header time in seconds since the epoch
    pub bitcoin_time: u32,
    /// Bitcoin address of the miner that found the block
    pub miner_bitcoin_address: String,
}

/// The value half of a FoundBlocks entry, encoded with bitcoin consensus
/// encoding.
struct FoundBlockValue {
    share_blockhash: BlockHash,
    bitcoin_time: u32,
    miner_bitcoin_address: String,
}

impl Encodable for FoundBlockValue {
    fn consensus_encode<W: bitcoin::io::Write + ?Sized>(
        &self,
        writer: &mut W,
    ) -> Result<usize, bitcoin::io::Error> {
        let mut length = 0;
        length += self.share_blockhash.consensus_encode(writer)?;
        length += self.bitcoin_time.consensus_encode(writer)?;
        length += self.miner_bitcoin_address.consensus_encode(writer)?;
        Ok(length)
    }
}

impl Decodable for FoundBlockValue {
    fn consensus_decode<R: bitcoin::io::Read + ?Sized>(
        reader: &mut R,
    ) -> Result<Self, encode::Error> {
        Ok(FoundBlockValue {
            share_blockhash: BlockHash::consensus_decode(reader)?,
            bitcoin_time: u32::consensus_decode(reader)?,
            miner_bitcoin_address: String::consensus_decode(reader)?,
        })
    }
}

/// Build the FoundBlocks key: big endian bitcoin height, then blockhash.
fn found_block_key(bitcoin_height: u64, bitcoin_blockhash: &BlockHash) -> Vec<u8> {
    let mut key = Vec::with_capacity(HEIGHT_KEY_PREFIX_LENGTH + 32);
    key.extend_from_slice(&bitcoin_height.to_be_bytes());
    key.extend_from_slice(&encode::serialize(bitcoin_blockhash));
    key
}

impl Store {
    /// Record the bitcoin blocks carried by a share being confirmed.
    ///
    /// Checks the share's header and the headers of each of its uncles,
    /// and records every one that meets the bitcoin network target. Only
    /// header data is read, so this works for blocks promoted header-only
    /// below the prune height.
    ///
    /// Headers are read from the committed store, so the share and its
    /// uncles must have been stored in an earlier batch. A missing header
    /// is an error because confirmation requires it.
    pub(crate) fn record_found_blocks(
        &self,
        blockhash: &BlockHash,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<(), StoreError> {
        let header = self.get_required_share_header(blockhash)?;
        for uncle_hash in &header.uncles {
            let uncle_header = self.get_required_share_header(uncle_hash)?;
            self.put_found_block_if_bitcoin_block(&uncle_header, batch);
        }
        self.put_found_block_if_bitcoin_block(&header, batch);
        Ok(())
    }

    /// Read a share header, returning NotFound if it is absent.
    fn get_required_share_header(&self, blockhash: &BlockHash) -> Result<ShareHeader, StoreError> {
        self.get_share_header(blockhash)?
            .ok_or_else(|| StoreError::NotFound(format!("Share header not found for {blockhash}")))
    }

    /// Add a FoundBlocks entry for `header` if its bitcoin header meets
    /// the bitcoin network target.
    ///
    /// The entry is derived from the header alone, so writing it again
    /// when a share is re-confirmed after a reorg writes identical bytes.
    fn put_found_block_if_bitcoin_block(
        &self,
        header: &ShareHeader,
        batch: &mut rocksdb::WriteBatch,
    ) {
        if !header.meets_bitcoin_difficulty() {
            return;
        }
        let column_family = self.db.cf_handle(&ColumnFamily::FoundBlocks).unwrap();
        let key = found_block_key(header.bitcoin_height, &header.bitcoin_header.block_hash());
        let value = FoundBlockValue {
            share_blockhash: header.block_hash(),
            bitcoin_time: header.bitcoin_header.time,
            miner_bitcoin_address: header.miner_bitcoin_address.to_string(),
        };
        batch.put_cf(&column_family, key, encode::serialize(&value));
    }

    /// Return every found bitcoin block, ordered by bitcoin height.
    pub fn get_found_blocks(&self) -> Result<Vec<FoundBlock>, StoreError> {
        let column_family = self.db.cf_handle(&ColumnFamily::FoundBlocks).unwrap();
        let mut found_blocks = Vec::new();
        for item in self
            .db
            .iterator_cf(&column_family, rocksdb::IteratorMode::Start)
        {
            let (key, value) = item?;
            found_blocks.push(decode_found_block(&key, &value)?);
        }
        Ok(found_blocks)
    }
}

/// Decode a FoundBlocks entry from its key and value bytes.
fn decode_found_block(key: &[u8], value: &[u8]) -> Result<FoundBlock, StoreError> {
    let (height_bytes, blockhash_bytes) = key
        .split_at_checked(HEIGHT_KEY_PREFIX_LENGTH)
        .ok_or_else(|| StoreError::Serialization(format!("Found block key too short: {key:?}")))?;
    let bitcoin_height = u64::from_be_bytes(height_bytes.try_into().map_err(|_| {
        StoreError::Serialization(format!("Invalid found block height: {height_bytes:?}"))
    })?);
    let bitcoin_blockhash: BlockHash = encode::deserialize(blockhash_bytes)?;
    let decoded_value: FoundBlockValue = encode::deserialize(value)?;
    Ok(FoundBlock {
        bitcoin_height,
        bitcoin_blockhash,
        share_blockhash: decoded_value.share_blockhash,
        bitcoin_time: decoded_value.bitcoin_time,
        miner_bitcoin_address: decoded_value.miner_bitcoin_address,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TestShareBlockBuilder;
    use bitcoin::blockdata::constants::genesis_block;
    use tempfile::tempdir;

    #[test]
    fn test_confirmed_share_meeting_bitcoin_target_is_recorded() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();
        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // The regtest genesis header meets its own target, so this share
        // carries a bitcoin block.
        let mut share = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        share.header.bitcoin_header = genesis_block(bitcoin::Network::Regtest).header;
        store.push_to_confirmed_chain(&share).unwrap();

        let found_blocks = store.get_found_blocks().unwrap();
        assert_eq!(
            found_blocks,
            vec![FoundBlock {
                bitcoin_height: share.header.bitcoin_height,
                bitcoin_blockhash: share.header.bitcoin_header.block_hash(),
                share_blockhash: share.block_hash(),
                bitcoin_time: share.header.bitcoin_header.time,
                miner_bitcoin_address: share.header.miner_bitcoin_address.to_string(),
            }]
        );
    }

    #[test]
    fn test_confirmed_share_missing_bitcoin_target_is_not_recorded() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();
        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        let share = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        assert!(!share.header.meets_bitcoin_difficulty());
        store.push_to_confirmed_chain(&share).unwrap();

        assert_eq!(
            store.get_confirmed_at_height(1).unwrap(),
            share.block_hash()
        );
        assert!(store.get_found_blocks().unwrap().is_empty());
    }

    #[test]
    fn test_uncle_meeting_bitcoin_target_is_recorded_when_nephew_confirms() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();
        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        store.push_to_confirmed_chain(&share1).unwrap();

        // The uncle is a sibling of share1 that lost the share chain race
        // but carries a bitcoin block. It arrives after share1 with equal
        // work, so it stays off the candidate and confirmed chains.
        let mut uncle = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695793)
            .build();
        uncle.header.bitcoin_header = genesis_block(bitcoin::Network::Regtest).header;
        store.push_to_candidate_chain(&uncle).unwrap();
        let mut batch = Store::get_write_batch();
        store.add_share_block(&uncle, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();
        assert_eq!(
            store.get_confirmed_at_height(1).unwrap(),
            share1.block_hash()
        );
        assert!(store.get_found_blocks().unwrap().is_empty());

        let nephew = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .uncles(vec![uncle.block_hash()])
            .nonce(0xe9695794)
            .build();
        store.push_to_confirmed_chain(&nephew).unwrap();

        assert_eq!(
            store.get_confirmed_at_height(2).unwrap(),
            nephew.block_hash()
        );
        let found_blocks = store.get_found_blocks().unwrap();
        assert_eq!(found_blocks.len(), 1);
        assert_eq!(found_blocks[0].share_blockhash, uncle.block_hash());
        assert_eq!(
            found_blocks[0].bitcoin_blockhash,
            uncle.header.bitcoin_header.block_hash()
        );
    }

    #[test]
    fn test_header_only_share_meeting_bitcoin_target_is_recorded() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();
        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // Below the prune height a syncing node promotes shares header-only,
        // so recording must not need the share body.
        let mut share = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        share.header.bitcoin_header = genesis_block(bitcoin::Network::Regtest).header;
        store.push_to_candidate_chain(&share).unwrap();
        assert!(!store.share_block_exists(&share.block_hash()));

        let mut batch = Store::get_write_batch();
        store
            .record_found_blocks(&share.block_hash(), &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let found_blocks = store.get_found_blocks().unwrap();
        assert_eq!(found_blocks.len(), 1);
        assert_eq!(found_blocks[0].share_blockhash, share.block_hash());
    }

    #[test]
    fn test_record_found_blocks_errors_when_header_missing() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();
        let share = TestShareBlockBuilder::new().nonce(0xe9695792).build();

        let mut batch = Store::get_write_batch();
        let result = store.record_found_blocks(&share.block_hash(), &mut batch);

        assert!(matches!(result, Err(StoreError::NotFound(_))));
    }
}
