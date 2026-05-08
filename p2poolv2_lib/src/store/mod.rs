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

use crate::shares::share_block::ShareBlock;
use crate::store::block_tx_metadata::{BlockMetadata, Status};
use crate::store::column_families::ColumnFamily;
use bitcoin::consensus::{Encodable, encode};
use bitcoin::{BlockHash, Work};
use rocksdb::{ColumnFamilyDescriptor, DB, Options as RocksDbOptions};
use std::sync::{Arc, RwLock};
use tracing::debug;
use writer::StoreError;

pub mod block_tx_metadata;
pub mod column_families;
pub mod dag_store;
pub mod organise;
mod pplns_shares;
mod prune_shares;
pub mod share_store;
pub mod stored_user;
pub mod transaction_store;
pub mod user;
pub mod writer;

/// A store for share blocks.
/// RocksDB as is used as the underlying database.
/// We use column families to store different types of data, so that compactions are independent for each type.
/// Key Value stores in column families:
/// - block: share blocks
/// - block_txids: txids for a block, to get transactions for a block. A tx can appear in multiple blocks.
/// - inputs: inputs for a transaction, to get inputs for a tx.
/// - outputs: outputs for a transaction, to get outputs for a tx. These can be marked as spent. So these are updated.
#[allow(dead_code)]
pub struct Store {
    path: String,
    db: DB,
    // Thread-safe chain state for use by ChainStore
    genesis_blockhash: Arc<RwLock<Option<BlockHash>>>,
}

/// Merge operator for appending BlockHashes to a Vec<BlockHash>.
///
/// This allows atomic append operations without read-modify-write cycles.
///
/// Registered via `set_merge_operator_associative`, so the same function
/// handles both full merge and partial merge:
/// - Full merge: `existing_val` is the base value from a prior Put/merge
///   result (a serialized `Vec<BlockHash>`) or `None`.
/// - Partial merge: `existing_val` is `Some(left_operand)` where the left
///   operand may be a raw 32-byte `BlockHash` OR a previously merged
///   `Vec<BlockHash>`. Operands may also be either format.
///
/// Each value passed in (existing_val or operand) is parsed by trying
/// `Vec<BlockHash>` first, then falling back to a single `BlockHash`.
fn blockhash_list_merge(
    _key: &[u8],
    existing_val: Option<&[u8]>,
    operands: &rocksdb::MergeOperands,
) -> Option<Vec<u8>> {
    let mut blockhashes: Vec<BlockHash> = match existing_val {
        Some(bytes) => parse_blockhash_bytes(bytes)?,
        None => Vec::new(),
    };

    for op in operands {
        for hash in parse_blockhash_bytes(op)? {
            if !blockhashes.contains(&hash) {
                blockhashes.push(hash);
            }
        }
    }

    let mut result = Vec::new();
    blockhashes.consensus_encode(&mut result).ok()?;
    Some(result)
}

/// Parse bytes as either a single raw 32-byte `BlockHash` or a
/// serialized `Vec<BlockHash>` (compact_size length prefix + N hashes).
///
/// Disambiguation is by length: a raw `BlockHash` is always exactly
/// 32 bytes, while a serialized `Vec<BlockHash>` is never 32 bytes
/// (0 elements = 1 byte, 1 element = 33 bytes, 2 elements = 65 bytes,
/// etc.). This avoids relying on `encode::deserialize` trial order,
/// which is unsafe because `deserialize` does not require full input
/// consumption -- a 32-byte hash starting with 0x00 would decode as
/// an empty Vec, silently losing the hash.
///
/// Returns `None` on unrecognised input so the merge operator can
/// propagate the failure to RocksDB instead of silently discarding data.
fn parse_blockhash_bytes(bytes: &[u8]) -> Option<Vec<BlockHash>> {
    const BLOCKHASH_LEN: usize = 32;
    if bytes.len() == BLOCKHASH_LEN {
        let hash = encode::deserialize::<BlockHash>(bytes).ok()?;
        return Some(vec![hash]);
    }
    let hashes = encode::deserialize::<Vec<BlockHash>>(bytes).ok()?;
    Some(hashes)
}

/// A rocksdb based store for share blocks.
/// We use column families to store different types of data, so that compactions are independent for each type.
#[allow(dead_code)]
impl Store {
    /// Create a new share store
    pub fn new(path: String, read_only: bool) -> Result<Self, StoreError> {
        // for now we use default options for all column families, we can tweak this later based on performance testing
        let block_metadata_cf_descriptor =
            ColumnFamilyDescriptor::new(ColumnFamily::BlockMetadata, RocksDbOptions::default());
        let block_txids_cf =
            ColumnFamilyDescriptor::new(ColumnFamily::BlockTxids, RocksDbOptions::default());
        let inputs_cf =
            ColumnFamilyDescriptor::new(ColumnFamily::Inputs, RocksDbOptions::default());
        let outputs_cf =
            ColumnFamilyDescriptor::new(ColumnFamily::Outputs, RocksDbOptions::default());
        let tx_cf = ColumnFamilyDescriptor::new(ColumnFamily::Tx, RocksDbOptions::default());

        // Configure BlockIndex column family with merge operator for efficient appends
        let mut block_index_opts = RocksDbOptions::default();
        block_index_opts
            .set_merge_operator_associative("blockhash_list_merge", blockhash_list_merge);
        let block_index_cf =
            ColumnFamilyDescriptor::new(ColumnFamily::BlockIndex, block_index_opts);

        // Configure BlockHeight column family with merge operator for efficient appends
        let mut block_height_opts = RocksDbOptions::default();
        block_height_opts
            .set_merge_operator_associative("blockhash_list_merge", blockhash_list_merge);
        let block_height_cf =
            ColumnFamilyDescriptor::new(ColumnFamily::BlockHeight, block_height_opts);

        // Configure TxidsBlocks column family with merge operator for efficient appends
        // Each txid can be in multiple blocks - only one confirmed,
        // but other valid PoW blocks could have the txids
        let mut txids_blocks_opts = RocksDbOptions::default();
        txids_blocks_opts
            .set_merge_operator_associative("blockhash_list_merge", blockhash_list_merge);
        let txids_blocks_cf =
            ColumnFamilyDescriptor::new(ColumnFamily::TxidsBlocks, txids_blocks_opts);

        // Configure Uncles column family with merge operator for efficient appends.
        // Each Uncle can be included by multiple nephews.
        let mut uncles_opts = RocksDbOptions::default();
        uncles_opts.set_merge_operator_associative("blockhash_list_merge", blockhash_list_merge);
        let uncles_cf = ColumnFamilyDescriptor::new(ColumnFamily::Uncles, uncles_opts);

        let bitcoin_txids_cf =
            ColumnFamilyDescriptor::new(ColumnFamily::BitcoinTxids, RocksDbOptions::default());

        let share_cf = ColumnFamilyDescriptor::new(ColumnFamily::Share, RocksDbOptions::default());
        let user_cf = ColumnFamilyDescriptor::new(ColumnFamily::User, RocksDbOptions::default());
        let user_index_cf =
            ColumnFamilyDescriptor::new(ColumnFamily::UserIndex, RocksDbOptions::default());
        let metadata_cf =
            ColumnFamilyDescriptor::new(ColumnFamily::Metadata, RocksDbOptions::default());

        let spends_index_cf =
            ColumnFamilyDescriptor::new(ColumnFamily::SpendsIndex, RocksDbOptions::default());

        let header_cf =
            ColumnFamilyDescriptor::new(ColumnFamily::Header, RocksDbOptions::default());

        let template_merkle_branches_cf = ColumnFamilyDescriptor::new(
            ColumnFamily::TemplateMerkleBranches,
            RocksDbOptions::default(),
        );

        let cfs = vec![
            block_metadata_cf_descriptor,
            block_txids_cf,
            txids_blocks_cf,
            uncles_cf,
            inputs_cf,
            outputs_cf,
            tx_cf,
            block_index_cf,
            block_height_cf,
            bitcoin_txids_cf,
            share_cf,
            user_cf,
            user_index_cf,
            metadata_cf,
            spends_index_cf,
            header_cf,
            template_merkle_branches_cf,
        ];

        // for the db too, we use default options for now
        let mut db_options = RocksDbOptions::default();
        db_options.create_missing_column_families(true);
        db_options.create_if_missing(true);
        let db = if read_only {
            DB::open_cf_descriptors_read_only(&db_options, path.clone(), cfs, false)?
        } else {
            DB::open_cf_descriptors(&db_options, path.clone(), cfs)?
        };
        let store = Self {
            path,
            db,
            // Initialise chain state fields
            genesis_blockhash: Arc::new(RwLock::new(None)),
        };
        Ok(store)
    }

    /// Get a rocksb write batch
    /// An associated function as batch is not obtained from db
    pub fn get_write_batch() -> rocksdb::WriteBatch {
        rocksdb::WriteBatch::default()
    }

    /// Commit a write batch earlier obtained using get batch
    pub fn commit_batch(&self, batch: rocksdb::WriteBatch) -> Result<(), rocksdb::Error> {
        self.db.write(batch)
    }

    /// Get all blockhashes from blockhash' height+1 up to top
    /// confirmed height.
    ///
    /// Walks the height index and collects all valid blocks at each
    /// height (confirmed, candidate, header-valid, block-valid).
    /// Pending and invalid blocks are excluded. Within each height,
    /// blocks are sorted lexicographically by blockhash for
    /// deterministic ordering. Heights are never split across batches
    /// -- all blocks at a height are included atomically.
    ///
    /// This produces a topologically sorted DAG subgraph because every
    /// block's parent is at height H-1, which is either in this batch
    /// or was sent in a previous batch.
    fn get_descendant_blockhashes(
        &self,
        blockhash: &BlockHash,
        stop_blockhash: &BlockHash,
        limit: usize,
    ) -> Result<Vec<BlockHash>, StoreError> {
        let mut blockhashes = Vec::with_capacity(limit);

        let start_height = match self.get_block_metadata(blockhash) {
            Ok(metadata) => metadata.expected_height.unwrap_or(0) + 1,
            Err(_) => 1,
        };

        let top_confirmed_height = match self.get_top_confirmed_height() {
            Ok(height) => height,
            Err(_) => return Ok(blockhashes),
        };

        for height in start_height..=top_confirmed_height {
            let mut hashes_at_height = self.get_blockhashes_for_height(height);
            hashes_at_height.retain(|hash| {
                self.get_block_metadata(hash)
                    .map(|metadata| {
                        metadata.status != Status::Pending && metadata.status != Status::Invalid
                    })
                    .unwrap_or(false)
            });
            hashes_at_height.sort();

            let found_stop = hashes_at_height.contains(stop_blockhash);
            blockhashes.extend(hashes_at_height);

            if found_stop || blockhashes.len() >= limit {
                return Ok(blockhashes);
            }
        }

        Ok(blockhashes)
    }

    /// Get genesis block hash from chain state
    pub fn get_genesis_blockhash(&self) -> Option<BlockHash> {
        *self.genesis_blockhash.read().unwrap()
    }

    /// Set genesis block hash in chain state
    pub fn set_genesis_blockhash(&self, hash: BlockHash) {
        *self.genesis_blockhash.write().unwrap() = Some(hash);
    }

    /// Get chain tip from the confirmed chain index.
    ///
    /// Returns the blockhash at the top confirmed height.
    pub fn get_chain_tip(&self) -> Result<BlockHash, StoreError> {
        let height = self.get_top_confirmed_height()?;
        self.get_confirmed_at_height(height)
    }

    /// Get total work of the confirmed chain tip
    pub fn get_total_work(&self) -> Result<Work, StoreError> {
        let tip = self.get_chain_tip()?;
        let metadata = self.get_block_metadata(&tip)?;
        Ok(metadata.chain_work)
    }

    /// Setup genesis block for the store
    /// Returns an error, if store already has even a single block
    pub fn setup_genesis(
        &self,
        genesis: &ShareBlock,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<(), StoreError> {
        let blockhash = genesis.block_hash();
        let genesis_work = genesis.header.get_work();
        self.add_share_header(&genesis.header, batch)?;
        self.add_share_block(genesis, batch)?;

        self.set_height_to_blockhash(&blockhash, 0, batch)?;
        let mut metadata = BlockMetadata {
            expected_height: Some(0),
            chain_work: genesis_work,
            status: Status::HeaderValid,
        };
        self.update_block_metadata(&blockhash, &metadata, batch)?;

        *self.genesis_blockhash.write().unwrap() = Some(blockhash);

        // Genesis is coinbase-only. No need to make sure to call
        // `add_spends_for_block`.
        assert_eq!(
            genesis.transactions.iter().len(),
            1,
            "Genesis should only have one transaction, the coinbase."
        );
        self.append_to_confirmed(&blockhash, 0, &mut metadata, batch)?;
        Ok(())
    }

    /// Initialise chain state from existing data in the store.
    /// Sets the genesis blockhash so chain tip and total work can be read from the confirmed chain index.
    pub fn init_chain_state_from_store(&self, genesis_hash: BlockHash) -> Result<(), StoreError> {
        self.set_genesis_blockhash(genesis_hash);
        debug!(
            "Initialised chain state: tip={}, height={}, work={}",
            self.get_chain_tip()?,
            self.get_top_confirmed_height()?,
            self.get_total_work()?,
        );
        Ok(())
    }
}

#[cfg(test)]
impl Store {
    /// Organise a share header into the candidate chain.
    ///
    /// Computes height and chain_work from parent metadata, creates
    /// BlockMetadata, and updates the candidate chain.
    /// Returns the new candidate height, or None.
    pub fn push_to_candidate_chain(&self, share: &ShareBlock) -> Result<Option<u32>, StoreError> {
        let mut batch = Store::get_write_batch();
        let result = self.organise_header(&share.header, &mut batch)?;
        self.commit_batch(batch)?;
        Ok(result)
    }

    /// Push a share to the confirmed chain: organise header, store
    /// the full block, then promote candidates to confirmed.
    /// Returns the new confirmed height if changed, or None.
    pub fn push_to_confirmed_chain(&self, share: &ShareBlock) -> Result<Option<u32>, StoreError> {
        self.push_to_candidate_chain(share)?;
        let mut batch = Store::get_write_batch();
        self.add_share_block(share, &mut batch)?;
        self.commit_batch(batch)?;
        let mut batch = Store::get_write_batch();
        let result = self.organise_block(&mut batch)?;
        self.commit_batch(batch)?;
        Ok(result)
    }

    /// Store a share block and create Valid metadata for it.
    ///
    /// Used for shares that arrive out of order and need to be
    /// discoverable by forward walks and uncle lookups. The metadata
    /// height and chain_work are computed from the parent if available,
    /// or default to height 1 with just the share's own work.
    /// Does NOT go through organise_header, so it avoids candidate
    /// chain side effects.
    pub fn store_with_valid_metadata(&self, share: &ShareBlock) {
        let blockhash = share.block_hash();
        let share_work = share.header.get_work();
        let (height, chain_work) = match self.get_block_metadata(&share.header.prev_share_blockhash)
        {
            Ok(parent_metadata) => {
                let parent_height = parent_metadata.expected_height.unwrap_or_default();
                (parent_height + 1, parent_metadata.chain_work + share_work)
            }
            Err(_) => (1, share_work),
        };
        let mut batch = Store::get_write_batch();
        self.add_share_block(share, &mut batch).unwrap();
        self.set_height_to_blockhash(&blockhash, height, &mut batch)
            .unwrap();
        let metadata = BlockMetadata {
            expected_height: Some(height),
            chain_work,
            status: Status::HeaderValid,
        };
        self.update_block_metadata(&blockhash, &metadata, &mut batch)
            .unwrap();
        self.commit_batch(batch).unwrap();
    }

    /// Create Valid metadata for a share without storing its block data.
    ///
    /// Also stores the header in the Header CF so that downstream
    /// children can look up parent timestamps and heights. Used to set
    /// up metadata for intermediate shares so that downstream children
    /// can compute their cumulative height and work correctly, even
    /// when the intermediate share has not arrived yet in the test
    /// scenario.
    pub fn create_valid_metadata_only(&self, share: &ShareBlock) {
        let blockhash = share.block_hash();
        let share_work = share.header.get_work();
        let (height, chain_work) = match self.get_block_metadata(&share.header.prev_share_blockhash)
        {
            Ok(parent_metadata) => {
                let parent_height = parent_metadata.expected_height.unwrap_or_default();
                (parent_height + 1, parent_metadata.chain_work + share_work)
            }
            Err(_) => (1, share_work),
        };
        let mut batch = Store::get_write_batch();
        self.add_share_header(&share.header, &mut batch).unwrap();
        self.set_height_to_blockhash(&blockhash, height, &mut batch)
            .unwrap();
        let metadata = BlockMetadata {
            expected_height: Some(height),
            chain_work,
            status: Status::HeaderValid,
        };
        self.update_block_metadata(&blockhash, &metadata, &mut batch)
            .unwrap();
        self.commit_batch(batch).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TestShareBlockBuilder;
    use crate::test_utils::multiplied_compact_target_as_work;
    use bitcoin::consensus;
    use bitcoin::hashes::Hash;
    use tempfile::tempdir;

    #[test_log::test]
    fn test_chain_state_management() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Create test shares in a linear chain
        let share1 = TestShareBlockBuilder::new().build();

        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .work(2)
            .build();

        let share3 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share2.block_hash().to_string())
            .work(3)
            .build();

        let genesis_hash = share1.block_hash();

        // Setup genesis (share1 confirmed at height 0)
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&share1, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        assert_eq!(store.get_genesis_blockhash(), Some(genesis_hash));
        assert_eq!(store.get_chain_tip().unwrap(), genesis_hash);

        // Push share2 to confirmed (extends confirmed to height 1)
        store.push_to_confirmed_chain(&share2).unwrap();

        // Push share3 to confirmed (extends confirmed to height 2)
        store.push_to_confirmed_chain(&share3).unwrap();

        // Test initialization from store
        store.init_chain_state_from_store(genesis_hash).unwrap();

        // After initialization, tip and genesis should be readable from confirmed chain
        assert_eq!(store.get_chain_tip().unwrap(), share3.block_hash());
        assert_eq!(store.get_genesis_blockhash(), Some(genesis_hash));

        // Total work should reflect sum of work from confirmed chain
        assert_eq!(
            store.get_total_work().unwrap(),
            multiplied_compact_target_as_work(0x01e0377ae, 1)
                + multiplied_compact_target_as_work(0x01e0377ae, 2)
                + multiplied_compact_target_as_work(0x01e0377ae, 3)
        );
    }

    #[test]
    fn test_merge_operator_for_block_height() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let height = 100u32;

        // Create three different blockhashes
        let hash1 = BlockHash::from_byte_array([1u8; 32]);
        let hash2 = BlockHash::from_byte_array([2u8; 32]);
        let hash3 = BlockHash::from_byte_array([3u8; 32]);

        // Add hash1 at height 100
        let mut batch = Store::get_write_batch();
        store
            .set_height_to_blockhash(&hash1, height, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Verify hash1 is stored
        let hashes = store.get_blockhashes_for_height(height);
        assert_eq!(hashes.len(), 1);
        assert!(hashes.contains(&hash1));

        // Add hash2 at the same height using merge operator
        let mut batch = Store::get_write_batch();
        store
            .set_height_to_blockhash(&hash2, height, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Verify both hash1 and hash2 are stored
        let hashes = store.get_blockhashes_for_height(height);
        assert_eq!(hashes.len(), 2);
        assert!(hashes.contains(&hash1));
        assert!(hashes.contains(&hash2));

        // Add hash3 at the same height
        let mut batch = Store::get_write_batch();
        store
            .set_height_to_blockhash(&hash3, height, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Verify all three hashes are stored
        let hashes = store.get_blockhashes_for_height(height);
        assert_eq!(hashes.len(), 3);
        assert!(hashes.contains(&hash1));
        assert!(hashes.contains(&hash2));
        assert!(hashes.contains(&hash3));

        // Test deduplication - add hash1 again
        let mut batch = Store::get_write_batch();
        store
            .set_height_to_blockhash(&hash1, height, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Should still have only 3 hashes (no duplicate)
        let hashes = store.get_blockhashes_for_height(height);
        assert_eq!(hashes.len(), 3);
        assert!(hashes.contains(&hash1));
        assert!(hashes.contains(&hash2));
        assert!(hashes.contains(&hash3));
    }

    #[test]
    fn test_merge_operator_multiple_batches() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let height = 200u32;

        let hash1 = BlockHash::from_byte_array([10u8; 32]);
        let hash2 = BlockHash::from_byte_array([20u8; 32]);
        let hash3 = BlockHash::from_byte_array([30u8; 32]);

        // Add multiple hashes in a single batch
        let mut batch = Store::get_write_batch();
        store
            .set_height_to_blockhash(&hash1, height, &mut batch)
            .unwrap();
        store
            .set_height_to_blockhash(&hash2, height, &mut batch)
            .unwrap();
        store
            .set_height_to_blockhash(&hash3, height, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Verify all hashes are stored correctly
        let hashes = store.get_blockhashes_for_height(height);
        assert_eq!(hashes.len(), 3);
        assert!(hashes.contains(&hash1));
        assert!(hashes.contains(&hash2));
        assert!(hashes.contains(&hash3));
    }

    /// Tests parse_blockhash_bytes handles both formats correctly.
    ///
    /// In partial merge mode, RocksDB passes raw 32-byte BlockHash
    /// operands. In full merge mode, existing_val is a serialized
    /// Vec<BlockHash>. The parse function must handle both.
    #[test]
    fn test_parse_blockhash_bytes_handles_raw_and_vec_formats() {
        let hash1 = BlockHash::from_byte_array([0xAAu8; 32]);
        let hash2 = BlockHash::from_byte_array([0xBBu8; 32]);

        // Raw 32-byte operand (as seen in partial merge)
        let raw_operand = consensus::serialize(&hash1);
        assert_eq!(raw_operand.len(), 32);
        let parsed = parse_blockhash_bytes(&raw_operand).expect("raw 32-byte operand should parse");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0], hash1);

        // Serialized Vec<BlockHash> (as seen in full merge existing_val)
        let vec_value = consensus::serialize(&vec![hash1, hash2]);
        assert_eq!(vec_value.len(), 65); // compact_size(2) + 32 + 32
        let parsed = parse_blockhash_bytes(&vec_value).expect("serialized Vec should parse");
        assert_eq!(parsed.len(), 2);
        assert!(parsed.contains(&hash1));
        assert!(parsed.contains(&hash2));

        // Hash with 0x00 first byte must NOT be misread as empty Vec
        let mut zero_prefix_bytes = [0x00u8; 32];
        zero_prefix_bytes[31] = 0x42;
        let zero_prefix_hash = BlockHash::from_byte_array(zero_prefix_bytes);
        let raw_zero = consensus::serialize(&zero_prefix_hash);
        let parsed = parse_blockhash_bytes(&raw_zero).expect("0x00-prefixed hash should parse");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0], zero_prefix_hash);

        // Empty input returns None (unrecognised format)
        assert!(parse_blockhash_bytes(&[]).is_none());

        // Garbage input returns None
        assert!(parse_blockhash_bytes(&[0xFF, 0xFF, 0xFF]).is_none());
    }

    /// Tests the merge operator with compaction forcing SST-level merges.
    ///
    /// Writes two hashes at the same height in separate flushes, then
    /// compacts. In a fresh DB compaction reaches the bottommost level
    /// (full merge with existing_val=None), so both hashes survive.
    /// This test verifies the baseline full-merge path works.
    #[test]
    fn test_merge_operator_survives_compaction() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let height = 3224u32;
        let hash1 = BlockHash::from_byte_array([0xAAu8; 32]);
        let hash2 = BlockHash::from_byte_array([0xBBu8; 32]);

        // Write hash1 in its own batch and flush to an SST file
        let mut batch = Store::get_write_batch();
        store
            .set_height_to_blockhash(&hash1, height, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();
        let block_height_cf = store.db.cf_handle(&ColumnFamily::BlockHeight).unwrap();
        store
            .db
            .flush_cf(&block_height_cf)
            .expect("flush should succeed");

        // Write hash2 in a separate batch and flush to a second SST file
        let mut batch = Store::get_write_batch();
        store
            .set_height_to_blockhash(&hash2, height, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();
        store
            .db
            .flush_cf(&block_height_cf)
            .expect("flush should succeed");

        // Force compaction -- this triggers partial merge on the two
        // merge operands sitting in separate SST files
        store
            .db
            .compact_range_cf(&block_height_cf, None::<&[u8]>, None::<&[u8]>);

        // After compaction, both hashes must still be present
        let hashes = store.get_blockhashes_for_height(height);
        assert_eq!(
            hashes.len(),
            2,
            "Both hashes should survive compaction, got: {:?}",
            hashes
        );
        assert!(hashes.contains(&hash1), "hash1 lost after compaction");
        assert!(hashes.contains(&hash2), "hash2 lost after compaction");
    }

    /// Verifies that parse_blockhash_bytes correctly handles a
    /// partial-merge result (serialized Vec) appearing as an operand.
    #[test]
    fn test_parse_blockhash_bytes_handles_partial_merge_result_as_operand() {
        let hash1 = BlockHash::from_byte_array([0xCCu8; 32]);
        let hash2 = BlockHash::from_byte_array([0xDDu8; 32]);

        // A partial merge result is a serialized Vec<BlockHash>
        let partial_merge_result = consensus::serialize(&vec![hash1, hash2]);
        assert_eq!(partial_merge_result.len(), 65);

        // parse_blockhash_bytes must extract both hashes
        let parsed = parse_blockhash_bytes(&partial_merge_result)
            .expect("partial merge result should parse");
        assert_eq!(parsed.len(), 2);
        assert!(parsed.contains(&hash1));
        assert!(parsed.contains(&hash2));
    }

    #[test]
    fn test_merge_operator_different_heights() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let hash1 = BlockHash::from_byte_array([100u8; 32]);
        let hash2 = BlockHash::from_byte_array([200u8; 32]);

        // Add hash1 at height 100 and hash2 at height 200
        let mut batch = Store::get_write_batch();
        store
            .set_height_to_blockhash(&hash1, 100, &mut batch)
            .unwrap();
        store
            .set_height_to_blockhash(&hash2, 200, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Verify hashes are stored at correct heights
        let hashes_100 = store.get_blockhashes_for_height(100);
        assert_eq!(hashes_100.len(), 1);
        assert!(hashes_100.contains(&hash1));

        let hashes_200 = store.get_blockhashes_for_height(200);
        assert_eq!(hashes_200.len(), 1);
        assert!(hashes_200.contains(&hash2));
    }
}
