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

use super::block_tx_metadata::BlockMetadata;
use super::{ColumnFamily, Store, writer::StoreError};
use crate::shares::share_block::{ShareBlock, ShareHeader, ShareTransaction, Txids};
use bitcoin::BlockHash;
use bitcoin::consensus::{self, Encodable, encode};
use std::collections::HashMap;
use tracing::debug;

impl Store {
    /// Add a share to the store.
    ///
    /// Returns early if the block already exists (duplicate guard).
    /// Stores the header in the Header CF and transaction indexes in
    /// BlockTxids/BitcoinTxids CFs. Full share chain transactions are
    /// stored separately. All writes are done in a single atomic batch.
    pub fn add_share_block(
        &self,
        share: &ShareBlock,
        confirm_txs: bool,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<(), StoreError> {
        let blockhash = share.block_hash();

        // Skip if this block already exists in the store
        if self.share_block_exists(&blockhash) {
            debug!("Share block {blockhash} already exists in store, skipping");
            return Ok(());
        }

        debug!(
            "Adding share to store with {} txs: {:?} work: {:?}",
            share.transactions.len(),
            blockhash,
            share.header.get_work()
        );

        // Store transactions and get their metadata
        let txs_metadata = self.add_sharechain_txs(&share.transactions, confirm_txs, batch)?;

        let txids = Txids(txs_metadata.iter().map(|t| t.txid).collect());
        // Store block -> txids index
        self.add_block_to_txids_index(
            &blockhash,
            &txids,
            batch,
            b"_txids",
            ColumnFamily::BlockTxids,
        )?;

        self.add_txids_to_blocks_index(&blockhash, &txids, batch)?;

        // TODO: Stop storing bitcoin txids to store
        let bitcoin_txids = Txids(
            share
                .bitcoin_transactions
                .iter()
                .map(|tx| tx.compute_txid())
                .collect(),
        );
        // Store block -> bitcoin txids index
        self.add_block_to_txids_index(
            &blockhash,
            &bitcoin_txids,
            batch,
            b"_bitcoin_txids",
            ColumnFamily::BitcoinTxids,
        )?;

        // Update block index for parent
        self.update_block_index(&share.header.prev_share_blockhash, &blockhash, batch)?;

        // Store the header in the dedicated Header CF
        self.add_share_header(&share.header, batch)?;

        Ok(())
    }

    /// Store a share header in the dedicated Header column family.
    ///
    /// This is idempotent -- writing the same header twice is safe.
    /// Called during header sync (via organise_header) and when
    /// storing full blocks (via add_share_block).
    pub fn add_share_header(
        &self,
        header: &ShareHeader,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<(), StoreError> {
        let blockhash = header.block_hash();
        let header_cf = self.db.cf_handle(&ColumnFamily::Header).unwrap();
        let mut encoded_header = Vec::new();
        header.consensus_encode(&mut encoded_header)?;
        batch.put_cf::<&[u8], Vec<u8>>(&header_cf, blockhash.as_ref(), encoded_header);
        Ok(())
    }

    /// Check whether a share header exists in the Header column family.
    ///
    /// Uses key_may_exist as a fast negative filter, then confirms
    /// with a full read on a positive result since key_may_exist can
    /// return false positives.
    pub fn share_header_exists(&self, blockhash: &BlockHash) -> bool {
        let header_cf = self.db.cf_handle(&ColumnFamily::Header).unwrap();
        let serialized = consensus::serialize(blockhash);
        if !self.db.key_may_exist_cf(&header_cf, &serialized) {
            return false;
        }
        self.db
            .get_cf::<&[u8]>(&header_cf, &serialized)
            .ok()
            .flatten()
            .is_some()
    }

    /// Check whether a share block (full block data) exists in the store.
    ///
    /// Checks the BlockTxids CF for the txids key, since txids are
    /// written as part of add_share_block and their presence indicates
    /// the full block data has been stored.
    pub fn share_block_exists(&self, blockhash: &BlockHash) -> bool {
        let block_txids_cf = self.db.cf_handle(&ColumnFamily::BlockTxids).unwrap();
        let mut key = consensus::serialize(blockhash);
        key.extend_from_slice(b"_txids");
        self.db
            .get_cf::<&[u8]>(&block_txids_cf, &key)
            .ok()
            .flatten()
            .is_some()
    }

    /// Get a share from the store by reconstructing it from the Header CF
    /// and transaction CFs.
    ///
    /// Returns None if the header or txids are missing.
    pub fn get_share(&self, blockhash: &BlockHash) -> Option<ShareBlock> {
        debug!("Getting share from store: {:?}", blockhash);
        let header = match self.get_share_header(blockhash) {
            Ok(Some(header)) => header,
            _ => return None,
        };
        if !self.share_block_exists(blockhash) {
            return None;
        }
        let transactions: Vec<ShareTransaction> = self
            .get_txs_for_blockhash(blockhash, ColumnFamily::BlockTxids)
            .into_iter()
            .map(ShareTransaction)
            .collect();
        Some(ShareBlock {
            header,
            transactions,
            bitcoin_transactions: vec![],
            template_merkle_branches: vec![],
        })
    }

    /// Get current confirmed chain tip and find the ShareBlock for it.
    pub fn get_share_at_tip(&self) -> Option<ShareBlock> {
        let tip = self.get_chain_tip().ok()?;
        self.get_share(&tip)
    }

    /// Get share headers matching the vector of blockhashes from the Header CF.
    ///
    /// Returns (BlockHash, ShareHeader) pairs in the same order as the input,
    /// skipping any hashes not found. Preserving order and returning the
    /// blockhash avoids callers needing to recompute block_hash().
    pub fn get_share_headers(
        &self,
        blockhashes: &[BlockHash],
    ) -> Result<Vec<(BlockHash, ShareHeader)>, StoreError> {
        debug!("Getting share headers from store: {:?}", blockhashes);
        let header_cf = self.db.cf_handle(&ColumnFamily::Header).unwrap();
        let keys = blockhashes
            .iter()
            .map(|h| (&header_cf, consensus::serialize(h)))
            .collect::<Vec<_>>();
        let results = self.db.multi_get_cf(keys);
        let mut share_headers = Vec::with_capacity(blockhashes.len());
        for (blockhash, result) in blockhashes.iter().zip(results.into_iter()) {
            if let Ok(Some(data)) = result {
                if let Ok(header) = encode::deserialize::<ShareHeader>(&data) {
                    share_headers.push((*blockhash, header));
                }
            }
        }
        Ok(share_headers)
    }

    /// Find the first blockhash that exists by checking the Header CF.
    pub(crate) fn get_first_existing_blockhash(&self, locator: &[BlockHash]) -> Option<BlockHash> {
        for blockhash in locator {
            if self.share_header_exists(blockhash) {
                return Some(*blockhash);
            }
        }
        None
    }

    /// Get multiple shares from the store by reconstructing each from
    /// the Header CF and transaction CFs.
    pub fn get_shares(
        &self,
        blockhashes: &[BlockHash],
    ) -> Result<HashMap<BlockHash, ShareBlock>, StoreError> {
        debug!("Getting shares from store: {:?}", blockhashes);
        let found_shares = blockhashes
            .iter()
            .filter_map(|blockhash| {
                let share = self.get_share(blockhash)?;
                Some((*blockhash, share))
            })
            .collect();
        Ok(found_shares)
    }

    /// Set the height for the blockhash, storing it in a vector of blockhashes for that height
    /// We are fine with Vector instead of HashSet as we are not going to have a lot of blockhashes at the same height
    /// Uses merge operator for atomic append without read-modify-write
    pub fn set_height_to_blockhash(
        &self,
        blockhash: &BlockHash,
        height: u32,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<(), StoreError> {
        let column_family = self.db.cf_handle(&ColumnFamily::BlockHeight).unwrap();
        let mut key = b"h:".to_vec();
        let height_bytes = height.to_be_bytes();
        key.extend_from_slice(&height_bytes);

        // Serialize the single BlockHash to merge
        let mut serialized = Vec::new();
        blockhash.consensus_encode(&mut serialized)?;

        // Use merge operator to atomically append
        batch.merge_cf(&column_family, key, serialized);
        Ok(())
    }

    /// Get the blockhashes for a specific height
    pub fn get_blockhashes_for_height(&self, height: u32) -> Vec<BlockHash> {
        let column_family = self.db.cf_handle(&ColumnFamily::BlockHeight).unwrap();
        let mut key = b"h:".to_vec();
        let height_bytes = height.to_be_bytes();
        key.extend_from_slice(&height_bytes);

        match self.db.get_cf::<&[u8]>(&column_family, key.as_ref()) {
            Ok(Some(blockhashes)) => encode::deserialize(&blockhashes).unwrap_or_default(),
            Ok(None) | Err(_) => vec![],
        }
    }

    /// Get the shares for a specific height
    pub fn get_shares_at_height(
        &self,
        height: u32,
    ) -> Result<HashMap<BlockHash, ShareBlock>, StoreError> {
        let blockhashes = self.get_blockhashes_for_height(height);
        self.get_shares(&blockhashes)
    }

    /// Get the block metadata for a blockhash
    pub(crate) fn get_block_metadata(
        &self,
        blockhash: &BlockHash,
    ) -> Result<BlockMetadata, StoreError> {
        let block_metadata_cf = self.db.cf_handle(&ColumnFamily::BlockMetadata).unwrap();
        let metadata_key = consensus::serialize(blockhash);

        match self.db.get_cf::<&[u8]>(&block_metadata_cf, &metadata_key) {
            Ok(Some(metadata_serialized)) => match encode::deserialize(&metadata_serialized) {
                Ok(metadata) => Ok(metadata),
                Err(e) => Err(StoreError::Serialization(format!(
                    "Error deserializing block metadata: {e}"
                ))),
            },
            Ok(None) | Err(_) => Err(StoreError::NotFound(format!(
                "No metadata found for blockhash: {blockhash}"
            ))),
        }
    }

    /// Batch fetch block metadata for multiple blockhashes using multi_get_cf.
    ///
    /// Returns (BlockHash, BlockMetadata) pairs, silently skipping any
    /// blockhashes whose metadata is not found or fails to deserialize.
    pub(crate) fn get_block_metadata_batch(
        &self,
        blockhashes: &[BlockHash],
    ) -> Vec<(BlockHash, BlockMetadata)> {
        let block_metadata_cf = self.db.cf_handle(&ColumnFamily::BlockMetadata).unwrap();
        let keys: Vec<_> = blockhashes
            .iter()
            .map(|hash| (&block_metadata_cf, consensus::serialize(hash)))
            .collect();
        let results = self.db.multi_get_cf(keys);
        let mut metadata_results = Vec::with_capacity(blockhashes.len());
        for (blockhash, result) in blockhashes.iter().zip(results.into_iter()) {
            if let Ok(Some(data)) = result {
                if let Ok(metadata) = encode::deserialize::<BlockMetadata>(&data) {
                    metadata_results.push((*blockhash, metadata));
                }
            }
        }
        metadata_results
    }

    /// Check which blockhashes from the provided list are missing from the store.
    ///
    /// Uses share_header_exists, so "missing" means we have never seen this header.
    pub fn get_missing_blockhashes(&self, blockhashes: &[BlockHash]) -> Vec<BlockHash> {
        blockhashes
            .iter()
            .filter(|&hash| !self.share_header_exists(hash))
            .cloned()
            .collect()
    }

    /// Update block metadata for a blockhash
    pub(crate) fn update_block_metadata(
        &self,
        blockhash: &BlockHash,
        metadata: &BlockMetadata,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<(), StoreError> {
        let block_metadata_cf = self.db.cf_handle(&ColumnFamily::BlockMetadata).unwrap();
        let metadata_key = consensus::serialize(blockhash);

        let mut serialized = Vec::new();
        metadata.consensus_encode(&mut serialized)?;

        batch.put_cf(&block_metadata_cf, &metadata_key, serialized);
        Ok(())
    }

    /// Get a share header from the Header column family.
    pub fn get_share_header(
        &self,
        blockhash: &BlockHash,
    ) -> Result<Option<ShareHeader>, StoreError> {
        debug!("Getting share header from store: {:?}", blockhash);
        let header_cf = self.db.cf_handle(&ColumnFamily::Header).unwrap();
        match self.db.get_cf::<&[u8]>(&header_cf, blockhash.as_ref())? {
            Some(data) => {
                let header: ShareHeader = encode::deserialize(&data)?;
                Ok(Some(header))
            }
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TestShareBlockBuilder;
    use bitcoin::hashes::Hash;
    use tempfile::tempdir;

    #[test]
    fn test_setup_genesis() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();
        let genesis_block = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis_block, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();
        assert_eq!(
            store.get_genesis_blockhash().unwrap(),
            genesis_block.block_hash()
        );

        // verify we can get the share header for the genesis block
        let header = store.get_share_header(&genesis_block.block_hash()).unwrap();
        assert_eq!(header, Some(genesis_block.header.clone()));

        // verify there is nothing in the chain index for the genesis block
        let children = store
            .get_children_blockhashes(&genesis_block.block_hash())
            .unwrap();
        assert!(children.is_none());
    }

    #[test]
    fn test_add_share_header_and_exists() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let block = TestShareBlockBuilder::new().build();
        let blockhash = block.block_hash();

        assert!(!store.share_header_exists(&blockhash));

        let mut batch = Store::get_write_batch();
        store.add_share_header(&block.header, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        assert!(store.share_header_exists(&blockhash));

        // Verify round-trip: read back and compare
        let header_cf = store.db.cf_handle(&ColumnFamily::Header).unwrap();
        let raw = store
            .db
            .get_cf::<&[u8]>(&header_cf, blockhash.as_ref())
            .unwrap()
            .unwrap();
        let stored_header: ShareHeader = consensus::encode::deserialize(&raw).unwrap();
        assert_eq!(stored_header, block.header);
    }

    #[test]
    fn test_organise_header_stores_header_in_header_cf() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // Create a child share and organise its header (without storing the full block)
        let child = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();

        assert!(!store.share_header_exists(&child.block_hash()));

        let mut batch = Store::get_write_batch();
        store.organise_header(&child.header, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // Header should now be in the Header CF
        assert!(store.share_header_exists(&child.block_hash()));
    }

    #[test]
    fn test_setup_genesis_stores_header_in_header_cf() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        assert!(store.share_header_exists(&genesis.block_hash()));
    }

    #[test]
    fn test_chain_with_uncles() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Create genesis block with a specific nonce to avoid duplicate issues
        let genesis_block = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis_block, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // Create first share (child of genesis)
        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis_block.block_hash().to_string())
            .nonce(0xe9695792)
            .build();

        let mut batch = Store::get_write_batch();
        store.add_share_block(&share1, true, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // Create uncle (also child of genesis)
        let uncle1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis_block.block_hash().to_string())
            .nonce(0xe9695793) // Different nonce to get different hash
            .build();

        let mut batch = Store::get_write_batch();
        store.add_share_block(&uncle1, false, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // Create share2 referencing uncle1
        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .uncles(vec![uncle1.block_hash()])
            .nonce(0xe9695794)
            .build();

        let mut batch = Store::get_write_batch();
        store.add_share_block(&share2, true, &mut batch).unwrap();
        // Uncle block index updates are handled by organise_header, not
        // add_share_block. Manually register uncle->nephew entries here.
        for uncle_blockhash in &share2.header.uncles {
            store
                .update_block_index(uncle_blockhash, &share2.block_hash(), &mut batch)
                .unwrap();
        }
        store.commit_batch(batch).unwrap();

        // Verify chain structure
        // Genesis should have 2 children (share1 and uncle1)
        let genesis_children = store
            .get_children_blockhashes(&genesis_block.block_hash())
            .unwrap()
            .unwrap();
        assert_eq!(genesis_children.len(), 2);
        assert!(genesis_children.contains(&share1.block_hash()));
        assert!(genesis_children.contains(&uncle1.block_hash()));

        // Share1 should have 1 child (share2)
        let share1_children = store
            .get_children_blockhashes(&share1.block_hash())
            .unwrap()
            .unwrap();
        assert_eq!(share1_children.len(), 1);
        assert!(share1_children.contains(&share2.block_hash()));

        // Uncle1 should also have share2 as child (since share2 references it as uncle)
        let uncle1_children = store
            .get_children_blockhashes(&uncle1.block_hash())
            .unwrap()
            .unwrap();
        assert_eq!(uncle1_children.len(), 1);
        assert!(uncle1_children.contains(&share2.block_hash()));

        // Verify we can retrieve all shares
        assert!(store.get_share(&genesis_block.block_hash()).is_some());
        assert!(store.get_share(&share1.block_hash()).is_some());
        assert!(store.get_share(&uncle1.block_hash()).is_some());
        assert!(store.get_share(&share2.block_hash()).is_some());
    }

    #[test]
    fn test_store_share_block_with_transactions_should_retreive_txs() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();
        let block = TestShareBlockBuilder::new().build();
        let num_txs = block.transactions.len();
        let txs = block.transactions.clone();
        let mut batch = Store::get_write_batch();
        store.add_share_block(&block, true, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        let blockhash = block.block_hash();

        let result = store.get_share(&blockhash);
        assert!(result.is_some());
        let share = result.unwrap();
        assert_eq!(share.transactions.len(), num_txs);
        assert_eq!(share.transactions, txs);
    }

    #[test]
    fn test_get_share_header() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let block = TestShareBlockBuilder::new().build();
        let mut batch = Store::get_write_batch();
        store.add_share_block(&block, true, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        let header = store.get_share_header(&block.block_hash()).unwrap();
        assert_eq!(header, Some(block.header.clone()));
    }

    #[test]
    fn test_get_share_header_nonexistent() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let nonexistent_hash = BlockHash::all_zeros();
        let header = store.get_share_header(&nonexistent_hash).unwrap();
        assert!(header.is_none());
    }

    #[test]
    fn test_block_status_for_nonexistent_block() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let nonexistent_hash = BlockHash::all_zeros();
        let share = store.get_share(&nonexistent_hash);
        assert!(share.is_none());
    }

    #[test]
    fn test_share_block_exists_returns_false_for_missing_block() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let nonexistent_hash = BlockHash::all_zeros();
        assert!(!store.share_block_exists(&nonexistent_hash));
    }

    #[test]
    fn test_share_block_exists_returns_true_for_stored_block() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let block = TestShareBlockBuilder::new().build();
        let blockhash = block.block_hash();

        assert!(!store.share_block_exists(&blockhash));

        let mut batch = Store::get_write_batch();
        store.add_share_block(&block, true, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        assert!(store.share_block_exists(&blockhash));
    }

    #[test]
    fn test_add_share_block_stores_header_in_header_cf() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let block = TestShareBlockBuilder::new().build();
        let blockhash = block.block_hash();

        let mut batch = Store::get_write_batch();
        store.add_share_block(&block, true, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // Verify the header was written to the Header CF
        let header_cf = store.db.cf_handle(&ColumnFamily::Header).unwrap();
        let raw = store
            .db
            .get_cf::<&[u8]>(&header_cf, blockhash.as_ref())
            .unwrap();
        assert!(raw.is_some(), "Header should exist in Header CF");

        // Deserialize and verify it matches the original header
        let stored_header: ShareHeader = consensus::encode::deserialize(&raw.unwrap()).unwrap();
        assert_eq!(stored_header, block.header);
    }

    #[test]
    fn test_get_block_metadata_batch_returns_stored_metadata() {
        use crate::store::block_tx_metadata::{BlockMetadata, Status};
        use bitcoin::Work;

        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let block_a = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let block_b = TestShareBlockBuilder::new().nonce(0xe9695792).build();
        let hash_a = block_a.block_hash();
        let hash_b = block_b.block_hash();

        let metadata_a = BlockMetadata {
            expected_height: Some(1),
            chain_work: Work::from_le_bytes([1u8; 32]),
            status: Status::Candidate,
        };
        let metadata_b = BlockMetadata {
            expected_height: Some(2),
            chain_work: Work::from_le_bytes([2u8; 32]),
            status: Status::Confirmed,
        };

        let mut batch = Store::get_write_batch();
        store
            .update_block_metadata(&hash_a, &metadata_a, &mut batch)
            .unwrap();
        store
            .update_block_metadata(&hash_b, &metadata_b, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let results = store.get_block_metadata_batch(&[hash_a, hash_b]);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0], (hash_a, metadata_a));
        assert_eq!(results[1], (hash_b, metadata_b));
    }

    #[test]
    fn test_get_block_metadata_batch_skips_missing_blockhashes() {
        use crate::store::block_tx_metadata::{BlockMetadata, Status};
        use bitcoin::Work;

        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let block = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let stored_hash = block.block_hash();
        let missing_hash = BlockHash::all_zeros();

        let metadata = BlockMetadata {
            expected_height: Some(5),
            chain_work: Work::from_le_bytes([3u8; 32]),
            status: Status::HeaderValid,
        };

        let mut batch = Store::get_write_batch();
        store
            .update_block_metadata(&stored_hash, &metadata, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let results = store.get_block_metadata_batch(&[missing_hash, stored_hash]);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], (stored_hash, metadata));
    }

    #[test]
    fn test_get_block_metadata_batch_returns_empty_for_empty_input() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let results = store.get_block_metadata_batch(&[]);
        assert!(results.is_empty());
    }

    #[test]
    fn test_add_share_block_skips_duplicate() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let block = TestShareBlockBuilder::new().build();
        let blockhash = block.block_hash();

        // First add succeeds and stores the block
        let mut batch = Store::get_write_batch();
        store.add_share_block(&block, true, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();
        assert!(store.get_share(&blockhash).is_some());

        // Second add of the same block returns Ok without error
        let mut batch = Store::get_write_batch();
        let result = store.add_share_block(&block, true, &mut batch);
        assert!(result.is_ok());

        // The batch should be empty (no writes for duplicate)
        // We verify by checking the block is still retrievable and unchanged
        store.commit_batch(batch).unwrap();
        assert!(store.get_share(&blockhash).is_some());
    }
}
