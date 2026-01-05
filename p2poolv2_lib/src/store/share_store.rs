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

use super::block_tx_metadata::BlockMetadata;
use super::{ColumnFamily, Store};
use crate::shares::share_block::{ShareBlock, ShareHeader, StorageShareBlock, Txids};
use bitcoin::consensus::{self, Encodable, encode};
use bitcoin::{BlockHash, Work};
use std::collections::HashMap;
use std::error::Error;
use tracing::debug;

impl Store {
    /// Add a share to the store
    ///
    /// Uses StorageShareBlock to serialize the share so that
    /// transactions are not serialized with the block.
    ///
    /// Transactions are stored separately. All writes are done in a
    /// single atomic batch.
    ///
    /// Should be called for shares that have been validated for PoW
    /// and other static checks.
    pub fn add_share(
        &self,
        share: ShareBlock,
        height: u32,
        chain_work: Work,
        confirm_txs: bool,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let blockhash = share.block_hash();
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

        // Update block index for uncles
        for uncle_blockhash in &share.header.uncles {
            self.update_block_index(uncle_blockhash, &blockhash, batch)?;
        }

        self.set_height_to_blockhash(&blockhash, height, batch)?;
        let block_metadata = BlockMetadata {
            height: Some(height),
            chain_work,
        };
        self.set_block_metadata(&blockhash, &block_metadata, batch)?;

        // Add the share block itself
        let storage_share_block: StorageShareBlock = share.into();
        let block_cf = self.db.cf_handle(&ColumnFamily::Block).unwrap();
        let mut encoded_share_block = Vec::new();
        storage_share_block.consensus_encode(&mut encoded_share_block)?;
        batch.put_cf::<&[u8], Vec<u8>>(&block_cf, blockhash.as_ref(), encoded_share_block);

        Ok(())
    }

    /// Get a share from the store
    pub fn get_share(&self, blockhash: &BlockHash) -> Option<ShareBlock> {
        debug!("Getting share from store: {:?}", blockhash);
        let share_cf = self.db.cf_handle(&ColumnFamily::Block).unwrap();
        let share = match self.db.get_cf::<&[u8]>(&share_cf, blockhash.as_ref()) {
            Ok(Some(share)) => share,
            Ok(None) | Err(_) => return None,
        };
        let share: StorageShareBlock = match encode::deserialize(&share) {
            Ok(share) => share,
            Err(_) => return None,
        };
        let transactions = self.get_txs_for_blockhash(blockhash, ColumnFamily::BlockTxids);
        let bitcoin_transactions =
            self.get_txs_for_blockhash(blockhash, ColumnFamily::BitcoinTxids);
        let share = ShareBlock {
            header: share.header,
            transactions,
            bitcoin_transactions,
        };
        Some(share)
    }

    /// Get current chain tip and find the ShareBlock for it
    pub fn get_share_at_tip(&self) -> Option<ShareBlock> {
        let tip = self.get_chain_tip();
        self.get_share(&tip)
    }

    /// Get a share headers matching the vector of blockhashes
    pub fn get_share_headers(
        &self,
        blockhashes: &[BlockHash],
    ) -> Result<Vec<ShareHeader>, Box<dyn Error + Send + Sync>> {
        debug!("Getting share headers from store: {:?}", blockhashes);
        let share_cf = self.db.cf_handle(&ColumnFamily::Block).unwrap();
        let keys = blockhashes
            .iter()
            .map(|h| (&share_cf, consensus::serialize(h)))
            .collect::<Vec<_>>();
        let shares = self.db.multi_get_cf(keys);
        let share_headers = shares
            .into_iter()
            .map(|v| {
                if let Ok(Some(v)) = v {
                    if let Ok(storage_share) = encode::deserialize::<StorageShareBlock>(&v) {
                        Some(storage_share.header)
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        Ok(share_headers.into_iter().flatten().collect())
    }

    // Find the first blockhash that exists by checking key existence
    pub(crate) fn get_first_existing_blockhash(&self, locator: &[BlockHash]) -> Option<BlockHash> {
        let block_cf = self.db.cf_handle(&ColumnFamily::Block).unwrap();
        for blockhash in locator {
            if self
                .db
                .key_may_exist_cf(&block_cf, consensus::serialize(blockhash))
            {
                return Some(*blockhash);
            }
        }
        None
    }

    /// Get multiple shares from the store
    /// TODO: Refactor to use get_share
    pub fn get_shares(
        &self,
        blockhashes: &[BlockHash],
    ) -> Result<HashMap<BlockHash, ShareBlock>, Box<dyn Error + Send + Sync>> {
        debug!("Getting shares from store: {:?}", blockhashes);
        let share_cf = self.db.cf_handle(&ColumnFamily::Block).unwrap();
        let keys = blockhashes
            .iter()
            .map(|h| (&share_cf, consensus::serialize(h)))
            .collect::<Vec<_>>();
        let shares = self.db.multi_get_cf(keys);
        // iterate over the blockhashes and shares, filter out the ones that are not found or can't be deserialized
        // then convert the storage share to share block and return as a hashmap
        let found_shares = blockhashes
            .iter()
            .zip(shares)
            .filter_map(|(blockhash, result)| {
                if let Ok(Some(data)) = result {
                    if let Ok(storage_share) = encode::deserialize::<StorageShareBlock>(&data) {
                        let transactions =
                            self.get_txs_for_blockhash(blockhash, ColumnFamily::BlockTxids);
                        let bitcoin_transactions =
                            self.get_txs_for_blockhash(blockhash, ColumnFamily::BitcoinTxids);
                        Some((
                            *blockhash,
                            ShareBlock {
                                header: storage_share.header,
                                transactions,
                                bitcoin_transactions,
                            },
                        ))
                    } else {
                        tracing::warn!(
                            "Could not deserialize share for blockhash: {:?}",
                            blockhash
                        );
                        None
                    }
                } else {
                    None
                }
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
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let column_family = self.db.cf_handle(&ColumnFamily::BlockHeight).unwrap();
        let height_bytes = height.to_be_bytes();

        // Serialize the single BlockHash to merge
        let mut serialized = Vec::new();
        blockhash.consensus_encode(&mut serialized)?;

        // Use merge operator to atomically append
        batch.merge_cf(&column_family, height_bytes, serialized);
        Ok(())
    }

    /// Get the blockhashes for a specific height
    pub fn get_blockhashes_for_height(&self, height: u32) -> Vec<BlockHash> {
        let column_family = self.db.cf_handle(&ColumnFamily::BlockHeight).unwrap();
        let height_bytes = height.to_be_bytes();
        match self
            .db
            .get_cf::<&[u8]>(&column_family, height_bytes.as_ref())
        {
            Ok(Some(blockhashes)) => encode::deserialize(&blockhashes).unwrap_or_default(),
            Ok(None) | Err(_) => vec![],
        }
    }

    /// Get the shares for a specific height
    pub fn get_shares_at_height(
        &self,
        height: u32,
    ) -> Result<HashMap<BlockHash, ShareBlock>, Box<dyn Error + Send + Sync>> {
        let blockhashes = self.get_blockhashes_for_height(height);
        self.get_shares(&blockhashes)
    }

    /// Get the block metadata for a blockhash
    pub(crate) fn get_block_metadata(
        &self,
        blockhash: &BlockHash,
    ) -> Result<BlockMetadata, Box<dyn Error + Send + Sync>> {
        let block_metadata_cf = self.db.cf_handle(&ColumnFamily::Block).unwrap();

        let mut metadata_key = consensus::serialize(blockhash);
        metadata_key.extend_from_slice(b"_md");

        match self.db.get_cf::<&[u8]>(&block_metadata_cf, &metadata_key) {
            Ok(Some(metadata_serialized)) => match encode::deserialize(&metadata_serialized) {
                Ok(metadata) => Ok(metadata),
                Err(e) => Err(format!("Error deserializing block metadata: {e}").into()),
            },
            Ok(None) | Err(_) => {
                Err(format!("No metadata found for blockhash: {blockhash}").into())
            }
        }
    }

    /// Check which blockhashes from the provided list are missing from the store
    /// Returns a vector of blockhashes that are not present in the store
    pub fn get_missing_blockhashes(&self, blockhashes: &[BlockHash]) -> Vec<BlockHash> {
        let block_cf = self.db.cf_handle(&ColumnFamily::Block).unwrap();
        blockhashes
            .iter()
            .filter(|&hash| {
                !self
                    .db
                    .key_may_exist_cf(&block_cf, consensus::serialize(hash))
            })
            .cloned()
            .collect()
    }

    /// Set the block metadata for a blockhash
    fn set_block_metadata(
        &self,
        blockhash: &BlockHash,
        metadata: &BlockMetadata,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let block_metadata_cf = self.db.cf_handle(&ColumnFamily::Block).unwrap();

        let mut metadata_key = consensus::serialize(blockhash);
        metadata_key.extend_from_slice(b"_md");

        let mut serialized = Vec::new();
        metadata.consensus_encode(&mut serialized)?;

        batch.put_cf(&block_metadata_cf, &metadata_key, serialized);
        Ok(())
    }

    /// Mark a block as valid in the store
    pub fn set_block_valid(
        &self,
        _blockhash: &BlockHash,
        _valid: bool,
        _batch: &mut rocksdb::WriteBatch,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        Ok(()) // TODO
    }

    /// Get a share header from the store
    pub fn get_share_header(
        &self,
        blockhash: &BlockHash,
    ) -> Result<Option<ShareHeader>, Box<dyn Error + Send + Sync>> {
        debug!("Getting share header from store: {:?}", blockhash);
        let share_cf = self.db.cf_handle(&ColumnFamily::Block).unwrap();
        match self.db.get_cf::<&[u8]>(&share_cf, blockhash.as_ref()) {
            Ok(Some(share)) => {
                let storage_share: StorageShareBlock = encode::deserialize(&share)?;
                Ok(Some(storage_share.header))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(e.into()),
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
        store
            .setup_genesis(genesis_block.clone(), &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();
        assert_eq!(store.get_genesis_blockhash(), genesis_block.block_hash());

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
    fn test_chain_with_uncles() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Create genesis block with a specific nonce to avoid duplicate issues
        let genesis_block = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store
            .setup_genesis(genesis_block.clone(), &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Create first share (child of genesis)
        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis_block.block_hash().to_string())
            .nonce(0xe9695792)
            .build();

        let mut batch = Store::get_write_batch();
        store
            .add_share(
                share1.clone(),
                1,
                share1.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Create uncle (also child of genesis)
        let uncle1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis_block.block_hash().to_string())
            .nonce(0xe9695793) // Different nonce to get different hash
            .build();

        let mut batch = Store::get_write_batch();
        store
            .add_share(
                uncle1.clone(),
                1,
                uncle1.header.get_work(),
                false,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Create share2 referencing uncle1
        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .uncles(vec![uncle1.block_hash()])
            .nonce(0xe9695794)
            .build();

        let mut batch = Store::get_write_batch();
        store
            .add_share(
                share2.clone(),
                2,
                share2.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
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
        store
            .add_share(block.clone(), 0, block.header.get_work(), true, &mut batch)
            .unwrap();
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
        store
            .add_share(block.clone(), 0, block.header.get_work(), true, &mut batch)
            .unwrap();
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
}
