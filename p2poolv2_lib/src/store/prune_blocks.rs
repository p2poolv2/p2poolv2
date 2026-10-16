// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Block body pruning boundaries.
//!
//! Every boundary is derived from the candidate tip; nothing is persisted.
//! See `docs/architecture/pruning.md`.

use crate::accounting::payout::sharechain_pplns::pplns_window::{PRUNE_DEPTH, PRUNE_INTERVAL};
use crate::store::Store;
use crate::store::writer::StoreError;

/// Lowest height whose block body a node must hold for a candidate tip.
///
/// Blocks below it are promoted header-only and their bodies are never
/// fetched. The confirmation and ancestry gates use this boundary.
pub fn prune_height_for_tip(candidate_tip_height: u32) -> u32 {
    candidate_tip_height.saturating_sub(PRUNE_DEPTH as u32)
}

/// Height below which block bodies are deleted for a candidate tip.
///
/// Lags `prune_height_for_tip` by one `PRUNE_INTERVAL`, so a candidate tip
/// that drops by less than an interval never makes the gates demand a
/// deleted body, and peers slightly behind can still fetch bodies near the
/// boundary.
pub fn prune_target_for_tip(candidate_tip_height: u32) -> u32 {
    candidate_tip_height.saturating_sub((PRUNE_DEPTH + PRUNE_INTERVAL) as u32)
}

impl Store {
    /// The prune height for the current candidate tip.
    ///
    /// Returns 0 when there is no candidate tip yet. Store read errors are
    /// propagated.
    pub fn prune_height(&self) -> Result<u32, StoreError> {
        match self.get_top_candidate_height() {
            Ok(candidate_tip_height) => Ok(prune_height_for_tip(candidate_tip_height)),
            Err(StoreError::NotFound(_)) => Ok(0),
            Err(error) => Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::block_tx_metadata::{BlockMetadata, ChainMembership, Status};
    use crate::test_utils::TestShareBlockBuilder;
    use tempfile::tempdir;

    #[test]
    fn test_prune_height_for_tip_below_depth_is_zero() {
        assert_eq!(prune_height_for_tip(PRUNE_DEPTH as u32 - 1), 0);
    }

    #[test]
    fn test_prune_height_for_tip_above_depth() {
        assert_eq!(prune_height_for_tip(PRUNE_DEPTH as u32 + 7), 7);
    }

    #[test]
    fn test_prune_target_for_tip_lags_prune_height_by_interval() {
        let candidate_tip_height = (PRUNE_DEPTH + PRUNE_INTERVAL) as u32 + 7;
        assert_eq!(prune_target_for_tip(candidate_tip_height), 7);
        assert_eq!(
            prune_height_for_tip(candidate_tip_height),
            7 + PRUNE_INTERVAL as u32
        );
    }

    #[test]
    fn test_prune_target_for_tip_below_depth_and_interval_is_zero() {
        assert_eq!(prune_target_for_tip(PRUNE_DEPTH as u32), 0);
    }

    #[test]
    fn test_store_prune_height_without_candidate_tip_is_zero() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        assert_eq!(store.prune_height().unwrap(), 0);
    }

    #[test]
    fn test_store_prune_height_follows_candidate_tip() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();
        let share = TestShareBlockBuilder::new().build();
        let candidate_tip_height = PRUNE_DEPTH as u32 + 11;
        let mut metadata = BlockMetadata {
            expected_height: Some(candidate_tip_height),
            chain_work: share.header.get_work(),
            status: Status::HeaderValid,
            chain: ChainMembership::None,
        };
        let mut batch = Store::get_write_batch();
        store
            .append_to_candidates(
                &share.block_hash(),
                candidate_tip_height,
                &mut metadata,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        assert_eq!(store.prune_height().unwrap(), 11);
    }
}
