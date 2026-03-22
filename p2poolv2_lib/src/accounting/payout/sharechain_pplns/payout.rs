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

use crate::accounting::OutputPair;
use crate::accounting::payout::payout_distribution::{
    PayoutDistribution, append_proportional_distribution,
};
use crate::accounting::payout::sharechain_pplns::pplns_window::PplnsWindow;
#[cfg(test)]
#[mockall_double::double]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
#[cfg(not(test))]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
use bitcoin::{Address, Amount};
use std::error::Error;

/// Share chain PPLNS payout distribution.
///
/// Holds a PplnsWindow that incrementally maintains the weighted difficulty
/// aggregate across calls. Each call to fill_distribution_from_shares
/// updates the window and reads the cached aggregate directly.
pub struct Payout {
    pplns_window: PplnsWindow,
}

impl Payout {
    /// Create a new Payout with an empty PPLNS window.
    pub fn new() -> Self {
        Self {
            pplns_window: PplnsWindow::default(),
        }
    }
}

impl PayoutDistribution for Payout {
    /// Fill payout distribution from the incrementally maintained PPLNS window.
    fn fill_distribution_from_shares(
        &mut self,
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

        self.pplns_window.update(chain_store_handle)?;

        let address_difficulty_map = self.pplns_window.get_distribution(total_difficulty);

        if address_difficulty_map.is_empty() {
            distribution.push(OutputPair {
                address: bootstrap_address,
                amount: remaining_total_amount,
            });
            return Ok(());
        }

        append_proportional_distribution(
            &address_difficulty_map,
            remaining_total_amount,
            distribution,
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounting::payout::sharechain_pplns::pplns_window::{
        NEPHEW_BONUS_FACTOR, UNCLE_WEIGHT_FACTOR,
    };
    use crate::shares::chain::chain_store_handle::ConfirmedHeaderResult;
    use crate::shares::chain::chain_store_handle::MockChainStoreHandle;
    use crate::store::block_tx_metadata::{BlockMetadata, Status};
    use crate::test_utils::{
        PUBKEY_2G, PUBKEY_3G, PUBKEY_4G, PUBKEY_G, build_test_header, build_test_header_with_uncles,
    };
    use bitcoin::hashes::Hash;
    use bitcoin::{BlockHash, Work};
    use p2poolv2_config::StratumConfig;
    use std::collections::HashSet;

    fn make_test_config() -> crate::config::StratumConfig<crate::config::Parsed> {
        StratumConfig::new_for_test_default().parse().unwrap()
    }

    #[test]
    fn test_empty_chain_uses_bootstrap() {
        let genesis_hash = BlockHash::all_zeros();

        let mut mock = MockChainStoreHandle::default();
        mock.expect_get_chain_tip()
            .returning(move || Ok(genesis_hash));
        mock.expect_get_block_metadata().returning(|_| {
            Ok(BlockMetadata {
                expected_height: None,
                chain_work: Work::from_le_bytes([0u8; 32]),
                status: Status::Confirmed,
            })
        });

        let mut payout = Payout::new();
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

        let confirmed_headers = vec![ConfirmedHeaderResult {
            height: 0,
            blockhash: tip_hash,
            header: header.clone(),
        }];

        let mut mock = MockChainStoreHandle::default();
        mock.expect_get_chain_tip().returning(move || Ok(tip_hash));
        mock.expect_get_block_metadata().returning(move |_| {
            Ok(BlockMetadata {
                expected_height: Some(0),
                chain_work: Work::from_le_bytes([0u8; 32]),
                status: Status::Confirmed,
            })
        });
        mock.expect_get_confirmed_headers_in_range()
            .returning(move |_, _| Ok(confirmed_headers.clone()));
        mock.expect_get_share_headers()
            .returning(|_| Ok(Vec::new()));

        let mut payout = Payout::new();
        let config = make_test_config();
        let total_amount = Amount::from_sat(100_000_000);
        let result = payout
            .get_output_distribution(&mock, f64::MAX, total_amount, &config)
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

        // Newest-to-oldest order
        let confirmed_headers = vec![
            ConfirmedHeaderResult {
                height: 1,
                blockhash: header2.block_hash(),
                header: header2.clone(),
            },
            ConfirmedHeaderResult {
                height: 0,
                blockhash: header1.block_hash(),
                header: header1.clone(),
            },
        ];

        let mut mock = MockChainStoreHandle::default();
        mock.expect_get_chain_tip().returning(move || Ok(tip_hash));
        mock.expect_get_block_metadata().returning(move |_| {
            Ok(BlockMetadata {
                expected_height: Some(1),
                chain_work: Work::from_le_bytes([0u8; 32]),
                status: Status::Confirmed,
            })
        });
        mock.expect_get_confirmed_headers_in_range()
            .returning(move |_, _| Ok(confirmed_headers.clone()));
        mock.expect_get_share_headers()
            .returning(|_| Ok(Vec::new()));

        let mut payout = Payout::new();
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

        let confirmed_headers = vec![ConfirmedHeaderResult {
            height: 0,
            blockhash: tip_hash,
            header: nephew_header.clone(),
        }];
        let uncle_headers = vec![(uncle_hash, uncle_header)];

        let mut mock = MockChainStoreHandle::default();
        mock.expect_get_chain_tip().returning(move || Ok(tip_hash));
        mock.expect_get_block_metadata().returning(move |_| {
            Ok(BlockMetadata {
                expected_height: Some(0),
                chain_work: Work::from_le_bytes([0u8; 32]),
                status: Status::Confirmed,
            })
        });
        mock.expect_get_confirmed_headers_in_range()
            .returning(move |_, _| Ok(confirmed_headers.clone()));
        mock.expect_get_share_headers()
            .returning(move |_| Ok(uncle_headers.clone()));

        let mut payout = Payout::new();
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

        let confirmed_headers = vec![ConfirmedHeaderResult {
            height: 0,
            blockhash: tip_hash,
            header: nephew_header.clone(),
        }];
        let uncle_headers = vec![(uncle1_hash, uncle1_header), (uncle2_hash, uncle2_header)];

        let mut mock = MockChainStoreHandle::default();
        mock.expect_get_chain_tip().returning(move || Ok(tip_hash));
        mock.expect_get_block_metadata().returning(move |_| {
            Ok(BlockMetadata {
                expected_height: Some(0),
                chain_work: Work::from_le_bytes([0u8; 32]),
                status: Status::Confirmed,
            })
        });
        mock.expect_get_confirmed_headers_in_range()
            .returning(move |_, _| Ok(confirmed_headers.clone()));
        mock.expect_get_share_headers()
            .returning(move |_| Ok(uncle_headers.clone()));

        let mut payout = Payout::new();
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
        let single_share_difficulty = header1.get_difficulty();

        // Newest-to-oldest order
        let confirmed_headers = vec![
            ConfirmedHeaderResult {
                height: 2,
                blockhash: header3.block_hash(),
                header: header3.clone(),
            },
            ConfirmedHeaderResult {
                height: 1,
                blockhash: header2.block_hash(),
                header: header2.clone(),
            },
            ConfirmedHeaderResult {
                height: 0,
                blockhash: header1.block_hash(),
                header: header1.clone(),
            },
        ];

        let mut mock = MockChainStoreHandle::default();
        mock.expect_get_chain_tip().returning(move || Ok(tip_hash));
        mock.expect_get_block_metadata().returning(move |_| {
            Ok(BlockMetadata {
                expected_height: Some(2),
                chain_work: Work::from_le_bytes([0u8; 32]),
                status: Status::Confirmed,
            })
        });
        mock.expect_get_confirmed_headers_in_range()
            .returning(move |_, _| Ok(confirmed_headers.clone()));
        mock.expect_get_share_headers()
            .returning(|_| Ok(Vec::new()));

        let mut payout = Payout::new();
        let config = make_test_config();
        let total_amount = Amount::from_sat(100_000_000);

        // Set total_difficulty to just one share's difficulty -- should include
        // the first (newest) share only
        let result = payout
            .get_output_distribution(&mock, single_share_difficulty, total_amount, &config)
            .unwrap();

        // Only the newest share (header3) should be included
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].address.to_string(), miner3);
        assert_eq!(result[0].amount, total_amount);
    }

    #[test]
    fn test_difficulty_cutoff_two_of_three() {
        let genesis_hash = BlockHash::all_zeros();

        // Create 3 confirmed shares with different miners
        let header1 = build_test_header(&genesis_hash.to_string(), PUBKEY_G, 2);
        let header2 = build_test_header(&header1.block_hash().to_string(), PUBKEY_2G, 2);
        let header3 = build_test_header(&header2.block_hash().to_string(), PUBKEY_3G, 2);
        let miner2 = header2.miner_address.to_string();
        let miner3 = header3.miner_address.to_string();
        let tip_hash = header3.block_hash();

        let single_share_difficulty = header1.get_difficulty();

        // Newest-to-oldest order
        let confirmed_headers = vec![
            ConfirmedHeaderResult {
                height: 2,
                blockhash: header3.block_hash(),
                header: header3.clone(),
            },
            ConfirmedHeaderResult {
                height: 1,
                blockhash: header2.block_hash(),
                header: header2.clone(),
            },
            ConfirmedHeaderResult {
                height: 0,
                blockhash: header1.block_hash(),
                header: header1.clone(),
            },
        ];

        let mut mock = MockChainStoreHandle::default();
        mock.expect_get_chain_tip().returning(move || Ok(tip_hash));
        mock.expect_get_block_metadata().returning(move |_| {
            Ok(BlockMetadata {
                expected_height: Some(2),
                chain_work: Work::from_le_bytes([0u8; 32]),
                status: Status::Confirmed,
            })
        });
        mock.expect_get_confirmed_headers_in_range()
            .returning(move |_, _| Ok(confirmed_headers.clone()));
        mock.expect_get_share_headers()
            .returning(|_| Ok(Vec::new()));

        let mut payout = Payout::new();
        let config = make_test_config();
        let total_amount = Amount::from_sat(100_000_000);

        // Set total_difficulty to two shares' worth -- should include
        // only the two newest shares (header3 and header2)
        let result = payout
            .get_output_distribution(&mock, single_share_difficulty * 2.0, total_amount, &config)
            .unwrap();

        assert_eq!(result.len(), 2);
        let addresses: HashSet<String> =
            result.iter().map(|pair| pair.address.to_string()).collect();
        assert!(addresses.contains(&miner2));
        assert!(addresses.contains(&miner3));

        let total_distributed: Amount = result.iter().map(|pair| pair.amount).sum();
        assert_eq!(total_distributed, total_amount);
    }

    #[test]
    fn test_different_miners_with_uncles() {
        let genesis_hash = BlockHash::all_zeros();

        // Miner A: confirmed share at height 0
        let header_a = build_test_header(&genesis_hash.to_string(), PUBKEY_G, 2);
        let miner_a = header_a.miner_address.to_string();

        // Uncle by miner B, referenced by miner C's share
        let uncle_header = build_test_header(&genesis_hash.to_string(), PUBKEY_2G, 2);
        let uncle_hash = uncle_header.block_hash();
        let miner_b = uncle_header.miner_address.to_string();

        // Miner C: confirmed share at height 1 that references uncle
        let header_c = build_test_header_with_uncles(
            &header_a.block_hash().to_string(),
            PUBKEY_3G,
            2,
            vec![uncle_hash],
        );
        let miner_c = header_c.miner_address.to_string();
        let tip_hash = header_c.block_hash();

        // Newest-to-oldest order
        let confirmed_headers = vec![
            ConfirmedHeaderResult {
                height: 1,
                blockhash: header_c.block_hash(),
                header: header_c.clone(),
            },
            ConfirmedHeaderResult {
                height: 0,
                blockhash: header_a.block_hash(),
                header: header_a.clone(),
            },
        ];
        let uncle_headers = vec![(uncle_hash, uncle_header)];

        let mut mock = MockChainStoreHandle::default();
        mock.expect_get_chain_tip().returning(move || Ok(tip_hash));
        mock.expect_get_block_metadata().returning(move |_| {
            Ok(BlockMetadata {
                expected_height: Some(1),
                chain_work: Work::from_le_bytes([0u8; 32]),
                status: Status::Confirmed,
            })
        });
        mock.expect_get_confirmed_headers_in_range()
            .returning(move |_, _| Ok(confirmed_headers.clone()));
        mock.expect_get_share_headers()
            .returning(move |_| Ok(uncle_headers.clone()));

        let mut payout = Payout::new();
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
