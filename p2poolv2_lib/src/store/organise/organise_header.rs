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

use crate::{shares::share_block::ShareHeader, store::writer::StoreError};
use tracing::debug;

use super::{Chain, Height, Store};

impl Store {
    /// Organise a share header into the candidate chain.
    ///
    /// Reads block metadata, top candidate, and top confirmed from the store,
    /// then extends or reorgs the candidate chain as needed. Only requires a
    /// ShareHeader, not a full ShareBlock. Does not touch the confirmed chain.
    ///
    /// Returns the new candidate height and chain if the candidate chain
    /// changed, or None if unchanged.
    pub(crate) fn organise_header(
        &self,
        header: &ShareHeader,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<Option<(Height, Chain)>, StoreError> {
        let blockhash = header.block_hash();
        debug!(
            "organise_header called for {blockhash} with prev blockhash {}",
            header.prev_share_blockhash
        );

        let mut metadata = self.get_block_metadata(&blockhash)?;
        let top_candidate = self.get_top_candidate().ok();
        let Some(top_confirmed) = self.get_top_confirmed().ok() else {
            return Err(StoreError::Database(
                "organise_header called without a genesis block".into(),
            ));
        };

        debug!("top candidate {:?}", top_candidate);
        debug!("top confirmed {:?}", top_confirmed);

        if let Some(extended_height) =
            self.should_extend_candidates(header, &metadata, top_candidate.as_ref())?
        {
            debug!("Extending candidate");
            self.append_to_candidates(&blockhash, extended_height, &mut metadata, batch)?;

            // Committed candidates above confirmed are unaffected by the
            // append; read them, then add the newly written entry.
            let old_top = top_candidate
                .map(|top| top.height)
                .unwrap_or(top_confirmed.height);
            let mut candidates = self.get_candidates(top_confirmed.height + 1, old_top)?;
            candidates.push((extended_height, blockhash));

            let final_height = self.extend_candidates_with_children(
                extended_height,
                &blockhash,
                &mut candidates,
                batch,
            )?;
            debug!("new candidate height after extending candidates {final_height}");
            return Ok(Some((final_height, candidates)));
        }

        if self.should_reorg_candidate(&blockhash, &metadata, top_candidate.as_ref()) {
            let (new_height, reorg_chain) =
                self.reorg_candidate(&blockhash, top_candidate.as_ref(), batch)?;
            debug!("new candidate height after reorging candidates {new_height}");

            // Include committed candidates below the reorg branch point
            let branch_start = reorg_chain.first().map(|(height, _)| *height).unwrap_or(0);
            let mut full_chain = if branch_start > top_confirmed.height + 1 {
                self.get_candidates(top_confirmed.height + 1, branch_start - 1)?
            } else {
                Vec::new()
            };
            full_chain.extend(reorg_chain);

            // reorg_candidate always returns a non-empty chain
            let reorg_tip_hash = full_chain.last().expect("reorg chain is non-empty").1;
            let final_height = self.extend_candidates_with_children(
                new_height,
                &reorg_tip_hash,
                &mut full_chain,
                batch,
            )?;
            debug!("new candidate height after reorg + forward walk {final_height}");
            return Ok(Some((final_height, full_chain)));
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::organise::TopResult;
    use crate::test_utils::TestShareBlockBuilder;
    use tempfile::tempdir;

    #[test]
    fn test_organise_header_extends_first_candidate() {
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
            .add_share_block(&share, 1, share.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // No top candidate before organising
        assert!(store.get_top_candidate().is_err());

        let mut batch = Store::get_write_batch();
        let result = store.organise_header(&share.header, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // Candidate chain should be updated
        assert!(result.is_some());
        let (height, candidates) = result.unwrap();
        assert_eq!(height, 1);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0], (1, share.block_hash()));

        // Top candidate should be set
        assert_eq!(
            store.get_top_candidate().ok(),
            Some(TopResult {
                hash: share.block_hash(),
                height: 1,
                work: share.header.get_work(),
            })
        );
    }

    #[test]
    fn test_organise_header_noop_when_conditions_not_met() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // Make genesis a candidate at height 0
        let mut batch = Store::get_write_batch();
        let mut genesis_metadata = store.get_block_metadata(&genesis.block_hash()).unwrap();
        store
            .append_to_candidates(&genesis.block_hash(), 0, &mut genesis_metadata, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Add share (child of genesis) at height 1 with equal work (not more)
        let share = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share_block(&share, 1, share.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = Store::get_write_batch();
        let result = store.organise_header(&share.header, &mut batch).unwrap();

        // Candidate chain unchanged
        assert!(result.is_none());

        // Top candidate still genesis
        assert_eq!(
            store.get_top_candidate().ok(),
            Some(TopResult {
                hash: genesis.block_hash(),
                height: 0,
                work: genesis.header.get_work(),
            })
        );
    }

    #[test]
    fn test_organise_header_reorgs_when_fork_has_more_work() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // share1: candidate at h:1
        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        let mut batch = Store::get_write_batch();
        let mut metadata1 = store
            .add_share_block(&share1, 1, share1.header.get_work(), true, &mut batch)
            .unwrap();
        store
            .append_to_candidates(&share1.block_hash(), 1, &mut metadata1, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // share2: candidate at h:2
        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(0xe9695793)
            .build();
        let mut batch = Store::get_write_batch();
        let mut metadata2 = store
            .add_share_block(&share2, 2, share2.header.get_work(), true, &mut batch)
            .unwrap();
        store
            .append_to_candidates(&share2.block_hash(), 2, &mut metadata2, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // fork_share: child of share1, h:2, MORE cumulative work
        let fork_share = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .work(2)
            .nonce(0xe9695794)
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share_block(
                &fork_share,
                2,
                fork_share.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Organise candidate with fork_share header
        let mut batch = Store::get_write_batch();
        let result = store
            .organise_header(&fork_share.header, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Candidate chain should be reorged
        assert!(result.is_some());
        let (_height, candidates) = result.unwrap();
        // Chain should contain share1 and fork_share
        assert!(
            candidates
                .iter()
                .any(|(_, hash)| *hash == fork_share.block_hash())
        );

        // Top candidate should be fork_share
        let top = store.get_top_candidate().unwrap();
        assert_eq!(top.hash, fork_share.block_hash());
    }
}
