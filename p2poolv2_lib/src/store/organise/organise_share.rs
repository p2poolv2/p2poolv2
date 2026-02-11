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

use crate::{
    shares::share_block::ShareBlock,
    store::{block_tx_metadata::BlockMetadata, writer::StoreError},
};

use super::Store;
use bitcoin::{BlockHash, Work};

impl Store {
    /// Organise a share by updating candidate and confirmed indexes.
    ///
    /// All writes go into the provided `WriteBatch` so the caller can
    /// commit them atomically.
    ///
    /// This atomicity is the only reason organise_share is in
    /// Store. We could provide a way to expose WriteBatch, but we'd
    /// still need to find a way to send all updates in a single event
    /// through StoreWriter, which will make things slightly more
    /// complicated to "organise" - pun intended.
    pub(crate) fn organise_share(
        &self,
        share: ShareBlock,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<(), StoreError> {
        let blockhash = share.block_hash();
        tracing::debug!("organise_share called for {blockhash} (no-op)");

        // Read the metadata and share from store as this function is called from
        let metadata = self.get_block_metadata(&blockhash)?;
        let top_candidate = self.get_top_candidate().ok();
        let top_confirmed = self.get_top_confirmed().ok();

        if let Some(extended_candidate_height) =
            self.extend_candidates_at(&share, &metadata, top_candidate)?
        {
            self.append_to_candidates(&blockhash, extended_candidate_height, batch)
        } else {
            Ok(())
        }

        // if self.should_reorg_candidates(&share, &metadata, top_candidate) {
        //     return self.reorg_candidates(&blockhash);
        // }

        // if let Some(extended_confirmed_height) =
        //     self.extend_confirmed_at(&share, &metadata, top_confirmed)?
        // {
        //     return self.make_confirmed(&blockhash, extended_confirmed_height, &mut batch);
        // }

        // if self.should_reorg_confirmed(&share, &metadata, top_confirmed) {
        //     return self.reorg_confirmed(&blockhash);
        // }
    }

    /// Extends candidate chain, if:
    /// 1. new share's height is one more than top candidate
    /// 2. new share's prev hash is top candidate hash
    /// 3. new share's chain work is more than top candidate's chain work.
    /// 4. Or, adds to candidate chain if it is empty.
    ///
    /// Returns true if candidate chain is extended.
    fn extend_candidates_at(
        &self,
        share: &ShareBlock,
        metadata: &BlockMetadata,
        top_candidate: Option<(BlockHash, u32, Work)>,
    ) -> Result<Option<u32>, StoreError> {
        match top_candidate {
            None => {
                if metadata.expected_height.unwrap_or_default() == 1 {
                    Ok(Some(1))
                } else {
                    Ok(None)
                }
            }
            Some((top_candidate_hash, top_candidate_height, top_work)) => {
                let expected_height = metadata.expected_height.unwrap_or_default();
                if top_candidate_hash == share.header.prev_share_blockhash
                    && expected_height == top_candidate_height + 1
                    && metadata.chain_work > top_work
                {
                    Ok(Some(expected_height))
                } else {
                    Ok(None)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TestShareBlockBuilder;
    use bitcoin::Work;
    use tempfile::tempdir;

    // ── extend_candidates_at unit tests ──────────────────────────────

    #[test]
    fn test_extend_candidates_at_returns_none_when_no_top_candidate() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let share = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let metadata = BlockMetadata {
            expected_height: Some(5),
            chain_work: share.header.get_work(),
        };

        let result = store.extend_candidates_at(&share, &metadata, None);
        assert_eq!(result.unwrap(), None);
    }

    #[test]
    fn test_extend_candidates_at_returns_height_when_conditions_match() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let parent = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let parent_hash = parent.block_hash();

        let share = TestShareBlockBuilder::new()
            .prev_share_blockhash(parent_hash.to_string())
            .nonce(0xe9695792)
            .build();

        let metadata = BlockMetadata {
            expected_height: Some(6),
            chain_work: share.header.get_work(),
        };

        // height == top candidate height + 1 → 6 == 5 + 1
        let top_candidate = Some((parent_hash, 5, Work::from_hex("0x05").unwrap()));

        let result = store.extend_candidates_at(&share, &metadata, top_candidate);
        assert_eq!(result.unwrap(), Some(6));
    }

    #[test]
    fn test_extend_candidates_at_returns_none_when_hash_mismatch() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let share = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let different_share = TestShareBlockBuilder::new().nonce(0xe9695792).build();
        let different_hash = different_share.block_hash();

        let metadata = BlockMetadata {
            expected_height: Some(6),
            chain_work: share.header.get_work(),
        };

        // Height condition met (6 == 5+1), but hash differs from prev_share_blockhash
        let top_candidate = Some((different_hash, 6, Work::from_hex("0x05").unwrap()));

        let result = store.extend_candidates_at(&share, &metadata, top_candidate);
        assert_eq!(result.unwrap(), None);
    }

    #[test]
    fn test_extend_candidates_at_returns_none_when_height_mismatch() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let parent = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let parent_hash = parent.block_hash();

        let share = TestShareBlockBuilder::new()
            .prev_share_blockhash(parent_hash.to_string())
            .nonce(0xe9695792)
            .build();

        let metadata = BlockMetadata {
            expected_height: Some(7),
            chain_work: share.header.get_work(),
        };

        // Hash matches but height doesn't (7 != 5+1)
        let top_candidate = Some((parent_hash, 5, Work::from_hex("0x05").unwrap()));

        let result = store.extend_candidates_at(&share, &metadata, top_candidate);
        assert_eq!(result.unwrap(), None);
    }

    #[test]
    fn test_extend_candidates_at_returns_none_when_both_mismatch() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let share = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let different_share = TestShareBlockBuilder::new().nonce(0xe9695792).build();
        let different_hash = different_share.block_hash();

        let metadata = BlockMetadata {
            expected_height: Some(5),
            chain_work: share.header.get_work(),
        };

        // Neither hash nor height matches
        let top_candidate = Some((different_hash, 10, Work::from_hex("0x05").unwrap()));

        let result = store.extend_candidates_at(&share, &metadata, top_candidate);
        assert_eq!(result.unwrap(), None);
    }

    // ── organise_share integration tests ─────────────────────────────

    #[test]
    fn test_organise_share_noop_when_no_top_candidate() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // Add a child share so its metadata is available
        let share = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(&share, 1, share.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // setup_genesis does not call append_to_candidate, so no top candidate
        assert!(store.get_top_candidate().is_err());

        let mut batch = Store::get_write_batch();
        store.organise_share(share.clone(), &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        assert_eq!(store.get_top_candidate_height().ok(), Some(1));
    }

    #[test]
    fn test_organise_share_extends_candidate_when_conditions_match() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // Add share1 (child of genesis) at height 1 and make it a candidate
        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(&share1, 1, share1.header.get_work(), true, &mut batch)
            .unwrap();
        store
            .append_to_candidates(&share1.block_hash(), 1, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        assert_eq!(
            store.get_top_candidate().ok(),
            Some((share1.block_hash(), 1, share1.header.get_work()))
        );

        // create share_to_organise with prev_share_blockhash = share1 at expected_height 2.
        // extend_candidates_at checks: hash, height and work conditions match
        let share_to_organise = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .work(2)
            .nonce(0xe9695793)
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(
                &share_to_organise,
                2,
                share_to_organise.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = Store::get_write_batch();
        store
            .organise_share(share_to_organise.clone(), &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        assert_eq!(
            store.get_candidate_at_height(2).unwrap(),
            share_to_organise.block_hash()
        );
        assert_eq!(
            store.get_candidate_at_height(1).ok(),
            Some(share1.block_hash())
        );
    }

    #[test]
    fn test_organise_share_noop_when_height_condition_not_met() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // Make genesis a candidate at height 0
        let mut batch = Store::get_write_batch();
        store
            .append_to_candidates(&genesis.block_hash(), 0, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        assert_eq!(
            store.get_top_candidate().ok(),
            Some((genesis.block_hash(), 0, genesis.header.get_work()))
        );

        // Add share (child of genesis) at height 1.
        // extend_candidates_at checks: hash matches but height does'nt
        let share = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(&share, 1, share.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = Store::get_write_batch();
        store.organise_share(share.clone(), &mut batch).unwrap();

        // No candidate at height 1
        assert!(store.get_candidate_at_height(1).is_err());
        // Top candidate unchanged
        assert_eq!(
            store.get_top_candidate().ok(),
            Some((genesis.block_hash(), 0, genesis.header.get_work()))
        );
    }
}
