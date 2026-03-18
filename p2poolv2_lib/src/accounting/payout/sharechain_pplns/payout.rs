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

//! Share chain PPLNS payout distribution implementation.
//!
//! Walks the confirmed share chain, applies uncle weighting (9/10 for uncles,
//! 1/10 bonus for nephews), and distributes payouts proportionally by
//! weighted difficulty.

use super::ShareChainPplnsShare;
use crate::accounting::OutputPair;
use crate::accounting::payout::payout_distribution::{
    PayoutDistribution, append_proportional_distribution,
};
#[cfg(test)]
#[mockall_double::double]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
#[cfg(not(test))]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
use crate::store::dag_store::ShareDag;
use bitcoin::{Address, Amount};
use std::collections::HashMap;
use std::error::Error;
use tracing::warn;

/// Maximum PPLNS window duration: two weeks in seconds.
const MAX_PPLNS_WINDOW_SECONDS: u32 = 2 * 7 * 24 * 60 * 60;

/// Estimated shares per second on the share chain (approximately 6 per minute).
/// Used to estimate the minimum height for the PPLNS window query.
/// We use a conservative multiplier (2x) to avoid missing shares due to
/// variable block times.
const ESTIMATED_MAX_SHARES_IN_WINDOW: u32 = MAX_PPLNS_WINDOW_SECONDS / 10 * 2;

/// Uncle weight factor: uncles receive 90% of their difficulty.
const UNCLE_WEIGHT_FACTOR: f64 = 0.9;

/// Nephew bonus factor: nephews receive 10% of each uncle's difficulty as bonus.
const NEPHEW_BONUS_FACTOR: f64 = 0.1;

/// Share chain PPLNS payout distribution.
///
/// Computes payout distribution from confirmed share chain headers
/// with uncle weighting applied.
pub struct Payout;

impl Payout {
    /// Get the PPLNS window ShareDag from the chain store.
    ///
    /// Computes the height range from the tip, fetches the ShareDag,
    /// then filters confirmed headers by the two-week time window.
    fn get_pplns_share_dag(
        &self,
        chain_store_handle: &ChainStoreHandle,
    ) -> Result<ShareDag, Box<dyn Error + Send + Sync>> {
        let tip_height = chain_store_handle.get_tip_height()?;
        let Some(tip_height) = tip_height else {
            return Ok(ShareDag::empty());
        };

        let tip_blockhash = chain_store_handle.get_chain_tip()?;
        let tip_header = chain_store_handle.get_share_header(&tip_blockhash)?;
        let earliest_allowed_time = tip_header.time.saturating_sub(MAX_PPLNS_WINDOW_SECONDS);

        let estimated_min_height = tip_height.saturating_sub(ESTIMATED_MAX_SHARES_IN_WINDOW);
        let mut share_dag = chain_store_handle.get_share_dag(estimated_min_height, tip_height)?;

        share_dag.filter_confirmed_by_time(earliest_allowed_time);

        Ok(share_dag)
    }

    /// Accumulate weighted difficulty per miner address from a ShareDag.
    ///
    /// For each confirmed share:
    /// - Full difficulty from the share's bits target
    /// - Plus 10% of each referenced uncle's difficulty as nephew bonus
    ///
    /// For each uncle:
    /// - 90% of the uncle's difficulty
    ///
    /// Stops accumulating once accumulated difficulty reaches total_difficulty.
    ///
    /// Returns a map from miner address string to total weighted difficulty
    /// for proportional payout distribution.
    fn accumulate_weighted_difficulty(
        &self,
        share_dag: &ShareDag,
        total_difficulty: f64,
    ) -> HashMap<String, f64> {
        let estimated_miners = share_dag.confirmed_headers.len() + share_dag.uncle_headers.len();
        let mut address_difficulty_map: HashMap<String, f64> =
            HashMap::with_capacity(estimated_miners);
        let mut accumulated_difficulty: f64 = 0.0;

        for (blockhash, header) in &share_dag.confirmed_headers {
            let share_difficulty = header.get_difficulty();
            let mut nephew_bonus: f64 = 0.0;

            if let Some(uncle_hashes) = share_dag.nephew_to_uncles.get(blockhash) {
                for uncle_hash in uncle_hashes {
                    let Some(uncle_header) = share_dag.uncle_headers.get(uncle_hash) else {
                        warn!("Uncle header not found for {uncle_hash}, skipping");
                        continue;
                    };

                    let uncle_difficulty = uncle_header.get_difficulty();

                    // Uncle gets 90% of its difficulty
                    let uncle_weighted_difficulty = uncle_difficulty * UNCLE_WEIGHT_FACTOR;
                    *address_difficulty_map
                        .entry(uncle_header.miner_address.to_string())
                        .or_insert(0.0) += uncle_weighted_difficulty;

                    // Uncle contributes its weighted difficulty to the PPLNS window
                    accumulated_difficulty += uncle_weighted_difficulty;

                    // Nephew gets 10% bonus per uncle's difficulty
                    nephew_bonus += uncle_difficulty * NEPHEW_BONUS_FACTOR;
                }
            }

            let weighted_difficulty = share_difficulty + nephew_bonus;
            *address_difficulty_map
                .entry(header.miner_address.to_string())
                .or_insert(0.0) += weighted_difficulty;

            // Confirmed share contributes its full difficulty to the PPLNS window
            accumulated_difficulty += share_difficulty;

            if accumulated_difficulty >= total_difficulty {
                return address_difficulty_map;
            }
        }

        address_difficulty_map
    }
}

impl PayoutDistribution<ShareChainPplnsShare> for Payout {
    /// Fill payout distribution from share chain confirmed shares with uncle weighting.
    fn fill_distribution_from_shares(
        &self,
        distribution: &mut Vec<OutputPair>,
        chain_store_handle: &ChainStoreHandle,
        total_difficulty: f64,
        _total_amount: bitcoin::Amount,
        remaining_total_amount: Amount,
        bootstrap_address: Address,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        if remaining_total_amount == Amount::ZERO {
            return Ok(());
        }

        if total_difficulty <= 0.0 {
            distribution.push(OutputPair {
                address: bootstrap_address,
                amount: remaining_total_amount,
            });
            return Ok(());
        }

        let share_dag = self.get_pplns_share_dag(chain_store_handle)?;

        if share_dag.confirmed_headers.is_empty() {
            distribution.push(OutputPair {
                address: bootstrap_address,
                amount: remaining_total_amount,
            });
            return Ok(());
        }

        let address_difficulty_map =
            self.accumulate_weighted_difficulty(&share_dag, total_difficulty);

        if address_difficulty_map.is_empty() {
            distribution.push(OutputPair {
                address: bootstrap_address,
                amount: remaining_total_amount,
            });
            return Ok(());
        }

        append_proportional_distribution(
            address_difficulty_map,
            remaining_total_amount,
            distribution,
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shares::chain::chain_store_handle::MockChainStoreHandle;
    use crate::shares::share_block::ShareHeader;
    use crate::store::dag_store::ShareDag;
    use crate::test_utils::{PUBKEY_2G, PUBKEY_3G, PUBKEY_4G, PUBKEY_G, TestShareBlockBuilder};
    use bitcoin::BlockHash;
    use bitcoin::hashes::Hash;
    use p2poolv2_config::StratumConfig;
    use std::collections::{HashMap, HashSet};

    /// Build a share header with a specific miner pubkey and work level.
    fn build_test_header(prev_hash: &str, miner_pubkey: &str, work: u32) -> ShareHeader {
        TestShareBlockBuilder::new()
            .prev_share_blockhash(prev_hash.to_string())
            .miner_pubkey(miner_pubkey)
            .work(work)
            .build()
            .header
    }

    /// Build a share header that references uncles.
    fn build_test_header_with_uncles(
        prev_hash: &str,
        miner_pubkey: &str,
        work: u32,
        uncles: Vec<BlockHash>,
    ) -> ShareHeader {
        TestShareBlockBuilder::new()
            .prev_share_blockhash(prev_hash.to_string())
            .miner_pubkey(miner_pubkey)
            .work(work)
            .uncles(uncles)
            .build()
            .header
    }

    fn make_test_config() -> crate::config::StratumConfig<crate::config::Parsed> {
        StratumConfig::new_for_test_default().parse().unwrap()
    }

    /// Build a ShareDag from confirmed headers with no uncles.
    fn build_dag_no_uncles(confirmed: Vec<(BlockHash, ShareHeader)>) -> ShareDag {
        ShareDag {
            confirmed_headers: confirmed,
            nephew_to_uncles: HashMap::new(),
            uncle_headers: HashMap::new(),
        }
    }

    /// Build a ShareDag from confirmed headers with uncle data.
    fn build_dag_with_uncles(
        confirmed: Vec<(BlockHash, ShareHeader)>,
        uncle_pairs: Vec<(BlockHash, ShareHeader)>,
    ) -> ShareDag {
        let (_, nephew_to_uncles) = ShareDag::collect_uncle_references(&confirmed);
        let uncle_headers: HashMap<BlockHash, ShareHeader> = uncle_pairs.into_iter().collect();
        ShareDag {
            confirmed_headers: confirmed,
            nephew_to_uncles,
            uncle_headers,
        }
    }

    /// Set up common mock expectations for tip height, chain tip, and share header.
    fn setup_tip_mocks(
        mock: &mut MockChainStoreHandle,
        tip_height: u32,
        tip_hash: BlockHash,
        tip_header: ShareHeader,
    ) {
        mock.expect_get_tip_height()
            .returning(move || Ok(Some(tip_height)));
        mock.expect_get_chain_tip().returning(move || Ok(tip_hash));
        mock.expect_get_share_header()
            .returning(move |_| Ok(tip_header.clone()));
    }

    #[test]
    fn test_empty_chain_uses_bootstrap() {
        let mut mock = MockChainStoreHandle::default();
        mock.expect_get_tip_height().returning(|| Ok(None));

        let payout = Payout;
        let config = make_test_config();
        let total_amount = Amount::from_sat(100_000_000);
        let result = payout
            .get_output_distribution(&mock, 1000.0, total_amount, &config)
            .unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].amount, total_amount);
    }

    #[test]
    fn test_single_share_no_uncles() {
        let genesis_hash = BlockHash::all_zeros();
        let header = build_test_header(&genesis_hash.to_string(), PUBKEY_G, 2);
        let miner_address = header.miner_address.to_string();
        let tip_hash = header.block_hash();

        let dag = build_dag_no_uncles(vec![(tip_hash, header.clone())]);

        let mut mock = MockChainStoreHandle::default();
        setup_tip_mocks(&mut mock, 0, tip_hash, header);
        mock.expect_get_share_dag()
            .returning(move |_, _| Ok(dag.clone()));

        let payout = Payout;
        let config = make_test_config();
        let total_amount = Amount::from_sat(100_000_000);
        let result = payout
            .get_output_distribution(&mock, 1.0, total_amount, &config)
            .unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].amount, total_amount);
        assert_eq!(result[0].address.to_string(), miner_address);
    }

    #[test]
    fn test_two_shares_equal_work_no_uncles() {
        let genesis_hash = BlockHash::all_zeros();
        let header1 = build_test_header(&genesis_hash.to_string(), PUBKEY_G, 2);
        let header2 = build_test_header(&header1.block_hash().to_string(), PUBKEY_2G, 2);
        let miner1 = header1.miner_address.to_string();
        let miner2 = header2.miner_address.to_string();
        let tip_hash = header2.block_hash();

        let dag = build_dag_no_uncles(vec![
            (header2.block_hash(), header2.clone()),
            (header1.block_hash(), header1.clone()),
        ]);

        let mut mock = MockChainStoreHandle::default();
        setup_tip_mocks(&mut mock, 1, tip_hash, header2);
        mock.expect_get_share_dag()
            .returning(move |_, _| Ok(dag.clone()));

        let payout = Payout;
        let config = make_test_config();
        let total_amount = Amount::from_sat(100_000_000);
        let result = payout
            .get_output_distribution(&mock, f64::MAX, total_amount, &config)
            .unwrap();

        assert_eq!(result.len(), 2);
        let total_distributed: Amount = result.iter().map(|pair| pair.amount).sum();
        assert_eq!(total_distributed, total_amount);

        // Both should get equal shares since they have equal work
        for pair in &result {
            assert_eq!(pair.amount, Amount::from_sat(50_000_000));
        }

        let addresses: HashSet<String> =
            result.iter().map(|pair| pair.address.to_string()).collect();
        assert!(addresses.contains(&miner1));
        assert!(addresses.contains(&miner2));
    }

    #[test]
    fn test_share_with_one_uncle() {
        let genesis_hash = BlockHash::all_zeros();

        // Uncle: a share not on the confirmed chain
        let uncle_header = build_test_header(&genesis_hash.to_string(), PUBKEY_3G, 2);
        let uncle_hash = uncle_header.block_hash();
        let uncle_difficulty = uncle_header.get_difficulty();
        let uncle_miner = uncle_header.miner_address.to_string();

        // Nephew: confirmed share that references the uncle
        let nephew_header =
            build_test_header_with_uncles(&genesis_hash.to_string(), PUBKEY_G, 2, vec![uncle_hash]);
        let nephew_difficulty = nephew_header.get_difficulty();
        let nephew_miner = nephew_header.miner_address.to_string();
        let tip_hash = nephew_header.block_hash();

        let dag = build_dag_with_uncles(
            vec![(tip_hash, nephew_header.clone())],
            vec![(uncle_hash, uncle_header)],
        );

        let mut mock = MockChainStoreHandle::default();
        setup_tip_mocks(&mut mock, 0, tip_hash, nephew_header);
        mock.expect_get_share_dag()
            .returning(move |_, _| Ok(dag.clone()));

        let payout = Payout;
        let config = make_test_config();
        let total_amount = Amount::from_sat(100_000_000);
        let result = payout
            .get_output_distribution(&mock, f64::MAX, total_amount, &config)
            .unwrap();

        // Uncle gets 90% of its difficulty, nephew gets base + 10% of uncle's difficulty
        let expected_uncle_weight = uncle_difficulty * UNCLE_WEIGHT_FACTOR;
        let expected_nephew_weight = nephew_difficulty + uncle_difficulty * NEPHEW_BONUS_FACTOR;
        let total_weight = expected_uncle_weight + expected_nephew_weight;

        let total_distributed: Amount = result.iter().map(|pair| pair.amount).sum();
        assert_eq!(total_distributed, total_amount);

        for pair in &result {
            let address_str = pair.address.to_string();
            if address_str == nephew_miner {
                let expected_sats = (total_amount.to_sat() as f64 * expected_nephew_weight
                    / total_weight)
                    .round() as u64;
                // Allow 1 sat rounding tolerance
                let diff = (pair.amount.to_sat() as i64 - expected_sats as i64).unsigned_abs();
                assert!(
                    diff <= 1,
                    "Nephew amount {actual} not close to expected {expected_sats}",
                    actual = pair.amount.to_sat()
                );
            } else if address_str == uncle_miner {
                let expected_sats = (total_amount.to_sat() as f64 * expected_uncle_weight
                    / total_weight)
                    .round() as u64;
                let diff = (pair.amount.to_sat() as i64 - expected_sats as i64).unsigned_abs();
                assert!(
                    diff <= 1,
                    "Uncle amount {actual} not close to expected {expected_sats}",
                    actual = pair.amount.to_sat()
                );
            }
        }
    }

    #[test]
    fn test_share_with_multiple_uncles() {
        let genesis_hash = BlockHash::all_zeros();

        let uncle1_header = build_test_header(&genesis_hash.to_string(), PUBKEY_3G, 2);
        let uncle2_header =
            build_test_header(&uncle1_header.block_hash().to_string(), PUBKEY_4G, 2);
        let uncle1_hash = uncle1_header.block_hash();
        let uncle2_hash = uncle2_header.block_hash();
        let uncle1_difficulty = uncle1_header.get_difficulty();
        let uncle2_difficulty = uncle2_header.get_difficulty();

        let nephew_header = build_test_header_with_uncles(
            &genesis_hash.to_string(),
            PUBKEY_G,
            2,
            vec![uncle1_hash, uncle2_hash],
        );
        let nephew_difficulty = nephew_header.get_difficulty();
        let tip_hash = nephew_header.block_hash();

        let dag = build_dag_with_uncles(
            vec![(tip_hash, nephew_header.clone())],
            vec![(uncle1_hash, uncle1_header), (uncle2_hash, uncle2_header)],
        );

        let mut mock = MockChainStoreHandle::default();
        setup_tip_mocks(&mut mock, 0, tip_hash, nephew_header);
        mock.expect_get_share_dag()
            .returning(move |_, _| Ok(dag.clone()));

        let payout = Payout;
        let config = make_test_config();
        let total_amount = Amount::from_sat(100_000_000);
        let result = payout
            .get_output_distribution(&mock, f64::MAX, total_amount, &config)
            .unwrap();

        // Nephew gets base + 10% of uncle1 + 10% of uncle2
        let expected_nephew_weight = nephew_difficulty
            + uncle1_difficulty * NEPHEW_BONUS_FACTOR
            + uncle2_difficulty * NEPHEW_BONUS_FACTOR;
        let expected_uncle1_weight = uncle1_difficulty * UNCLE_WEIGHT_FACTOR;
        let expected_uncle2_weight = uncle2_difficulty * UNCLE_WEIGHT_FACTOR;
        let total_weight = expected_nephew_weight + expected_uncle1_weight + expected_uncle2_weight;

        let total_distributed: Amount = result.iter().map(|pair| pair.amount).sum();
        assert_eq!(total_distributed, total_amount);

        // Verify weights are reasonable
        assert!(
            expected_nephew_weight > nephew_difficulty,
            "Nephew should have bonus"
        );
        assert!(total_weight > 0.0, "Total weight should be positive");
    }

    #[test]
    fn test_difficulty_cutoff() {
        let genesis_hash = BlockHash::all_zeros();

        // Create 3 confirmed shares, newest to oldest
        let header1 = build_test_header(&genesis_hash.to_string(), PUBKEY_G, 2);
        let header2 = build_test_header(&header1.block_hash().to_string(), PUBKEY_2G, 2);
        let header3 = build_test_header(&header2.block_hash().to_string(), PUBKEY_3G, 2);
        let miner3 = header3.miner_address.to_string();
        let tip_hash = header3.block_hash();

        // Difficulty per share (from bits)
        let difficulty_per_share = header1.get_difficulty();

        let dag = build_dag_no_uncles(vec![
            (header3.block_hash(), header3.clone()),
            (header2.block_hash(), header2.clone()),
            (header1.block_hash(), header1.clone()),
        ]);

        let mut mock = MockChainStoreHandle::default();
        setup_tip_mocks(&mut mock, 2, tip_hash, header3);
        mock.expect_get_share_dag()
            .returning(move |_, _| Ok(dag.clone()));

        let payout = Payout;
        let config = make_test_config();
        let total_amount = Amount::from_sat(100_000_000);

        // Set total_difficulty to just one share's difficulty -- should include
        // the first (newest) share only
        let result = payout
            .get_output_distribution(&mock, difficulty_per_share, total_amount, &config)
            .unwrap();

        // Only the newest share (header3) should be included
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].address.to_string(), miner3);
        assert_eq!(result[0].amount, total_amount);
    }

    #[test]
    fn test_time_cutoff() {
        let genesis_hash = BlockHash::all_zeros();

        // Recent share with current timestamp
        let recent_header = build_test_header(&genesis_hash.to_string(), PUBKEY_G, 2);
        let recent_miner = recent_header.miner_address.to_string();

        // Old share with timestamp beyond two weeks
        let mut old_header = build_test_header(&genesis_hash.to_string(), PUBKEY_2G, 2);
        // Set old header time to 3 weeks ago relative to recent
        old_header.time = recent_header.time.saturating_sub(3 * 7 * 24 * 60 * 60);

        let tip_hash = recent_header.block_hash();

        // The dag includes both -- time filtering happens in get_pplns_share_dag
        let dag = build_dag_no_uncles(vec![
            (recent_header.block_hash(), recent_header.clone()),
            (old_header.block_hash(), old_header.clone()),
        ]);

        let mut mock = MockChainStoreHandle::default();
        setup_tip_mocks(&mut mock, 1, tip_hash, recent_header);
        mock.expect_get_share_dag()
            .returning(move |_, _| Ok(dag.clone()));

        let payout = Payout;
        let config = make_test_config();
        let total_amount = Amount::from_sat(100_000_000);

        let result = payout
            .get_output_distribution(&mock, f64::MAX, total_amount, &config)
            .unwrap();

        // Only the recent share should be included (old one is beyond 2 weeks)
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].address.to_string(), recent_miner);
        assert_eq!(result[0].amount, total_amount);
    }

    #[test]
    fn test_different_miners_with_uncles() {
        let genesis_hash = BlockHash::all_zeros();

        // Miner A: confirmed share at height 1
        let header_a = build_test_header(&genesis_hash.to_string(), PUBKEY_G, 2);
        let miner_a = header_a.miner_address.to_string();

        // Uncle by miner B, referenced by miner C's share
        let uncle_header = build_test_header(&genesis_hash.to_string(), PUBKEY_2G, 2);
        let uncle_hash = uncle_header.block_hash();
        let miner_b = uncle_header.miner_address.to_string();

        // Miner C: confirmed share at height 2 that references uncle
        let header_c = build_test_header_with_uncles(
            &header_a.block_hash().to_string(),
            PUBKEY_3G,
            2,
            vec![uncle_hash],
        );
        let miner_c = header_c.miner_address.to_string();
        let tip_hash = header_c.block_hash();

        let dag = build_dag_with_uncles(
            vec![
                (header_c.block_hash(), header_c.clone()),
                (header_a.block_hash(), header_a.clone()),
            ],
            vec![(uncle_hash, uncle_header)],
        );

        let mut mock = MockChainStoreHandle::default();
        setup_tip_mocks(&mut mock, 1, tip_hash, header_c);
        mock.expect_get_share_dag()
            .returning(move |_, _| Ok(dag.clone()));

        let payout = Payout;
        let config = make_test_config();
        let total_amount = Amount::from_sat(100_000_000);

        let result = payout
            .get_output_distribution(&mock, f64::MAX, total_amount, &config)
            .unwrap();

        // Should have 3 addresses: miner A, miner B (uncle), miner C (nephew)
        let addresses: HashSet<String> =
            result.iter().map(|pair| pair.address.to_string()).collect();
        assert_eq!(addresses.len(), 3);
        assert!(addresses.contains(&miner_a));
        assert!(addresses.contains(&miner_b));
        assert!(addresses.contains(&miner_c));

        let total_distributed: Amount = result.iter().map(|pair| pair.amount).sum();
        assert_eq!(total_distributed, total_amount);
    }
}
