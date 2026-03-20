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

use crate::accounting::OutputPair;
use crate::accounting::payout::payout_distribution::{
    PayoutDistribution, append_proportional_distribution,
};
use crate::accounting::payout::simple_pplns::SimplePplnsShare;
#[cfg(test)]
#[mockall_double::double]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
#[cfg(not(test))]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
use bitcoin::{Address, Amount};
use std::collections::HashMap;
use std::error::Error;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct Payout {
    /// Step size in seconds for batch querying shares from storage.
    /// This determines how far back in time to query in each batch.
    /// Default: 86400 seconds (1 day) for typical pool configurations.
    step_size_seconds: u64,
}

impl PayoutDistribution<SimplePplnsShare> for Payout {
    fn fill_distribution_from_shares(
        &mut self,
        distribution: &mut Vec<OutputPair>,
        chain_store_handle: &ChainStoreHandle,
        total_difficulty: f64,
        total_amount: bitcoin::Amount,
        remaining_total_amount: Amount,
        bootstrap_address: Address,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        // Only calculate proportional distribution if there's remaining amount for miners
        // This avoids parsing miner addresses when 100% goes to donation/fee
        // This also avoids running PPLNS share look ups when we don't need to use that data
        if remaining_total_amount > bitcoin::Amount::ZERO {
            let address_difficulty_map =
                self.accumulate_difficulty_by_address(chain_store_handle, total_difficulty)?;

            if address_difficulty_map.is_empty() {
                *distribution = vec![OutputPair {
                    address: bootstrap_address,
                    amount: total_amount,
                }];
            } else {
                distribution.reserve(address_difficulty_map.len());

                append_proportional_distribution(
                    address_difficulty_map,
                    remaining_total_amount,
                    distribution,
                )?;
            }
        }

        Ok(())
    }
}

impl Payout {
    /// Creates a new Payout with specified step size.
    ///
    /// # Arguments
    /// * `step_size_seconds` - Batch size in seconds for querying shares from
    ///   Default: 86400 (1 day) for typical pool configurations
    pub fn new(step_size_seconds: u64) -> Self {
        Self { step_size_seconds }
    }

    /// Accumulate difficulty per miner address from PPLNS shares.
    ///
    /// Queries shares in time windows going backwards from the current time,
    /// accumulating difficulty per address directly into a HashMap. This avoids
    /// building an intermediate Vec of shares and a second grouping pass.
    ///
    /// Continues querying additional time windows if total difficulty hasn't
    /// been reached.
    fn accumulate_difficulty_by_address(
        &self,
        store: &ChainStoreHandle,
        total_difficulty: f64,
    ) -> Result<HashMap<String, f64>, Box<dyn Error + Send + Sync>> {
        let mut address_difficulty: HashMap<String, f64> = HashMap::new();
        let mut accumulated_difficulty = 0f64;

        // Start from current time and work backwards
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut end_time = current_time;
        let mut has_more_shares = true;

        // Query shares in batches going back in time
        while accumulated_difficulty < total_difficulty && has_more_shares {
            let start_time = end_time.saturating_sub(self.step_size_seconds);

            // Query shares for this time window
            let batch_shares =
                store.get_pplns_shares_filtered(None, Some(start_time), Some(end_time));

            has_more_shares = !batch_shares.is_empty();

            if has_more_shares {
                for share in batch_shares.into_iter() {
                    if accumulated_difficulty < total_difficulty {
                        accumulated_difficulty += share.difficulty as f64;
                        if let Some(btcaddress) = share.btcaddress {
                            *address_difficulty.entry(btcaddress).or_insert(0.0) +=
                                share.difficulty as f64;
                        }
                    }
                }

                // Move to the next time window (further back in time) if total diff not reached
                if accumulated_difficulty < total_difficulty {
                    end_time = start_time;
                }
            }
        }

        Ok(address_difficulty)
    }
}

#[cfg(test)]
mod tests {
    use p2poolv2_config::StratumConfig;

    use super::*;

    #[tokio::test]
    async fn test_accumulate_difficulty_exact_match() {
        let payout = Payout::new(86400);
        let mut chain_store_handle = ChainStoreHandle::default();

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Create shares with total difficulty of 1000 across 4 addresses
        let shares = vec![
            SimplePplnsShare::new(
                1,
                400,
                "addr1".to_string(),
                "worker1".to_string(),
                (current_time - 1800) * 1_000_000,
                "job".to_string(),
                "extra".to_string(),
                "nonce".to_string(),
            ),
            SimplePplnsShare::new(
                2,
                300,
                "addr2".to_string(),
                "worker2".to_string(),
                (current_time - 2400) * 1_000_000,
                "job".to_string(),
                "extra".to_string(),
                "nonce".to_string(),
            ),
            SimplePplnsShare::new(
                3,
                200,
                "addr3".to_string(),
                "worker3".to_string(),
                (current_time - 3000) * 1_000_000,
                "job".to_string(),
                "extra".to_string(),
                "nonce".to_string(),
            ),
            SimplePplnsShare::new(
                4,
                100,
                "addr4".to_string(),
                "worker4".to_string(),
                (current_time - 3600) * 1_000_000,
                "job".to_string(),
                "extra".to_string(),
                "nonce".to_string(),
            ),
        ];

        chain_store_handle
            .expect_get_pplns_shares_filtered()
            .return_const(shares);

        let result = payout
            .accumulate_difficulty_by_address(&chain_store_handle, 1000.0)
            .unwrap();

        // All 4 addresses should be present
        assert_eq!(result.len(), 4);
        assert_eq!(result.get("addr1"), Some(&400.0));
        assert_eq!(result.get("addr2"), Some(&300.0));
        assert_eq!(result.get("addr3"), Some(&200.0));
        assert_eq!(result.get("addr4"), Some(&100.0));

        // Verify total difficulty
        let total: f64 = result.values().sum();
        assert_eq!(total, 1000.0);
    }

    #[tokio::test]
    async fn test_accumulate_difficulty_cutoff() {
        let payout = Payout::new(86400);
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut chain_store_handle = ChainStoreHandle::default();

        // Four shares totalling 1000, but target is 750
        // Shares are processed in order: 400 + 300 + 200 = 900 >= 750, stops
        let shares = vec![
            SimplePplnsShare::new(
                1,
                400,
                "addr1".to_string(),
                "worker1".to_string(),
                (current_time - 1800) * 1_000_000,
                "job".to_string(),
                "extra".to_string(),
                "nonce".to_string(),
            ),
            SimplePplnsShare::new(
                2,
                300,
                "addr2".to_string(),
                "worker2".to_string(),
                (current_time - 2400) * 1_000_000,
                "job".to_string(),
                "extra".to_string(),
                "nonce".to_string(),
            ),
            SimplePplnsShare::new(
                3,
                200,
                "addr3".to_string(),
                "worker3".to_string(),
                (current_time - 3000) * 1_000_000,
                "job".to_string(),
                "extra".to_string(),
                "nonce".to_string(),
            ),
            SimplePplnsShare::new(
                4,
                100,
                "addr4".to_string(),
                "worker4".to_string(),
                (current_time - 3600) * 1_000_000,
                "job".to_string(),
                "extra".to_string(),
                "nonce".to_string(),
            ),
        ];

        chain_store_handle
            .expect_get_pplns_shares_filtered()
            .return_const(shares);

        let result = payout
            .accumulate_difficulty_by_address(&chain_store_handle, 750.0)
            .unwrap();

        // addr4 (100 difficulty) should not be included since cutoff reached at 900
        assert_eq!(result.len(), 3);
        assert_eq!(result.get("addr1"), Some(&400.0));
        assert_eq!(result.get("addr2"), Some(&300.0));
        assert_eq!(result.get("addr3"), Some(&200.0));
        assert!(result.get("addr4").is_none());

        let total: f64 = result.values().sum();
        assert_eq!(total, 900.0);
    }

    #[tokio::test]
    async fn test_accumulate_difficulty_insufficient_shares() {
        let payout = Payout::new(86400);
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut chain_store_handle = ChainStoreHandle::default();

        let shares = vec![
            SimplePplnsShare::new(
                1,
                100,
                "addr1".to_string(),
                "worker1".to_string(),
                (current_time - 1800) * 1_000_000,
                "job".to_string(),
                "extra".to_string(),
                "nonce".to_string(),
            ),
            SimplePplnsShare::new(
                2,
                200,
                "addr2".to_string(),
                "worker2".to_string(),
                (current_time - 2400) * 1_000_000,
                "job10".to_string(),
                "extra10".to_string(),
                "nonce10".to_string(),
            ),
        ];

        let mut seq = mockall::Sequence::new();

        chain_store_handle
            .expect_get_pplns_shares_filtered()
            .times(1)
            .in_sequence(&mut seq)
            .return_const(shares);

        chain_store_handle
            .expect_get_pplns_shares_filtered()
            .times(1)
            .in_sequence(&mut seq)
            .return_const(vec![]);

        let result = payout
            .accumulate_difficulty_by_address(&chain_store_handle, 500.0)
            .unwrap();

        // All available shares included even though total (300) < target (500)
        assert_eq!(result.len(), 2);
        assert_eq!(result.get("addr1"), Some(&100.0));
        assert_eq!(result.get("addr2"), Some(&200.0));

        let total: f64 = result.values().sum();
        assert_eq!(total, 300.0);
    }

    #[tokio::test]
    async fn test_accumulate_difficulty_empty_store() {
        let payout = Payout::new(86400);
        let mut chain_store_handle = ChainStoreHandle::default();

        chain_store_handle
            .expect_get_pplns_shares_filtered()
            .return_const(vec![]);

        let result = payout
            .accumulate_difficulty_by_address(&chain_store_handle, 1000.0)
            .unwrap();

        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_accumulate_difficulty_single_share_exceeds_target() {
        let payout = Payout::new(86400);
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut chain_store_handle = ChainStoreHandle::default();

        let shares = vec![SimplePplnsShare::new(
            1,
            1500,
            "addr1".to_string(),
            "worker1".to_string(),
            (current_time - 1800) * 1_000_000,
            "job".to_string(),
            "extra".to_string(),
            "nonce".to_string(),
        )];

        chain_store_handle
            .expect_get_pplns_shares_filtered()
            .return_const(shares);

        let result = payout
            .accumulate_difficulty_by_address(&chain_store_handle, 1000.0)
            .unwrap();

        // Single share included even though it exceeds target
        assert_eq!(result.len(), 1);
        assert_eq!(result.get("addr1"), Some(&1500.0));
    }

    #[tokio::test]
    async fn test_accumulate_difficulty_same_address_aggregation() {
        let payout = Payout::new(86400);
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut chain_store_handle = ChainStoreHandle::default();

        // Two shares from addr1, one from addr2 -- total difficulty 600
        let shares = vec![
            SimplePplnsShare::new(
                1,
                100,
                "addr1".to_string(),
                "worker1".to_string(),
                (current_time - 50) * 1_000_000,
                "job".to_string(),
                "extra".to_string(),
                "nonce".to_string(),
            ),
            SimplePplnsShare::new(
                2,
                200,
                "addr2".to_string(),
                "worker2".to_string(),
                (current_time - 150) * 1_000_000,
                "job".to_string(),
                "extra".to_string(),
                "nonce".to_string(),
            ),
            SimplePplnsShare::new(
                3,
                300,
                "addr1".to_string(),
                "worker3".to_string(),
                (current_time - 250) * 1_000_000,
                "job".to_string(),
                "extra".to_string(),
                "nonce".to_string(),
            ),
        ];

        let mut seq = mockall::Sequence::new();

        chain_store_handle
            .expect_get_pplns_shares_filtered()
            .times(1)
            .in_sequence(&mut seq)
            .return_const(shares);

        chain_store_handle
            .expect_get_pplns_shares_filtered()
            .times(1)
            .in_sequence(&mut seq)
            .return_const(vec![]);

        let result = payout
            .accumulate_difficulty_by_address(&chain_store_handle, 1000.0)
            .unwrap();

        // addr1 shares aggregated: 100 + 300 = 400
        assert_eq!(result.len(), 2);
        assert_eq!(result.get("addr1"), Some(&400.0));
        assert_eq!(result.get("addr2"), Some(&200.0));
    }

    #[tokio::test]
    async fn test_accumulate_difficulty_multiple_batches() {
        let payout = Payout::new(86400);
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut chain_store_handle = ChainStoreHandle::default();

        // First batch: shares from the most recent time window (total difficulty 300)
        let batch_one = vec![
            SimplePplnsShare::new(
                1,
                100,
                "addr1".to_string(),
                "worker1".to_string(),
                (current_time - 1800) * 1_000_000,
                "job".to_string(),
                "extra".to_string(),
                "nonce".to_string(),
            ),
            SimplePplnsShare::new(
                2,
                200,
                "addr2".to_string(),
                "worker2".to_string(),
                (current_time - 2400) * 1_000_000,
                "job".to_string(),
                "extra".to_string(),
                "nonce".to_string(),
            ),
        ];

        // Second batch: shares from the older time window (total difficulty 400)
        let batch_two = vec![
            SimplePplnsShare::new(
                3,
                150,
                "addr1".to_string(),
                "worker3".to_string(),
                (current_time - 90000) * 1_000_000,
                "job".to_string(),
                "extra".to_string(),
                "nonce".to_string(),
            ),
            SimplePplnsShare::new(
                4,
                250,
                "addr3".to_string(),
                "worker4".to_string(),
                (current_time - 100000) * 1_000_000,
                "job".to_string(),
                "extra".to_string(),
                "nonce".to_string(),
            ),
        ];

        let mut seq = mockall::Sequence::new();

        // First call returns batch_one (300 total difficulty < 600 target)
        chain_store_handle
            .expect_get_pplns_shares_filtered()
            .times(1)
            .in_sequence(&mut seq)
            .return_const(batch_one);

        // Second call returns batch_two (300 + 400 = 700 >= 600 target)
        chain_store_handle
            .expect_get_pplns_shares_filtered()
            .times(1)
            .in_sequence(&mut seq)
            .return_const(batch_two);

        let result = payout
            .accumulate_difficulty_by_address(&chain_store_handle, 600.0)
            .unwrap();

        // All shares from both batches should be included since batch_one (300)
        // is insufficient and batch_two pushes us over the 600 target.
        // addr1: 100 (batch 1) + 150 (batch 2) = 250
        // addr2: 200 (batch 1)
        // addr3: 250 (batch 2)
        assert_eq!(result.len(), 3);
        assert_eq!(result.get("addr1"), Some(&250.0));
        assert_eq!(result.get("addr2"), Some(&200.0));
        assert_eq!(result.get("addr3"), Some(&250.0));

        let total: f64 = result.values().sum();
        assert_eq!(total, 700.0);
    }

    #[tokio::test]
    async fn test_payout_constructors() {
        let payout1 = Payout::new(3600);
        assert_eq!(payout1.step_size_seconds, 3600);
    }

    #[tokio::test]
    async fn test_get_output_distribution_single_address() {
        let mut payout = Payout::new(86400);
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut chain_store_handle = ChainStoreHandle::default();

        let shares = vec![SimplePplnsShare::new(
            1,
            1000,
            "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq".to_string(),
            "worker1".to_string(),
            (current_time - 1800) * 1_000_000,
            "job".to_string(),
            "extra".to_string(),
            "nonce".to_string(),
        )];

        chain_store_handle
            .expect_get_pplns_shares_filtered()
            .return_const(shares);

        let total_amount = bitcoin::Amount::from_sat(50_000_000); // 0.5 BTC

        let stratum_config = StratumConfig::new_for_test_default().parse().unwrap();

        let result = payout
            .get_output_distribution(&chain_store_handle, 1000.0, total_amount, &stratum_config)
            .unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].amount, total_amount);
        assert_eq!(
            result[0].address.to_string(),
            "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
        );
    }

    #[tokio::test]
    async fn test_get_output_distribution_multiple_addresses() {
        let mut payout = Payout::new(86400);
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut chain_store_handle = ChainStoreHandle::default();

        let shares = vec![
            SimplePplnsShare::new(
                1,
                600,
                "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq".to_string(),
                "worker1".to_string(),
                (current_time - 1800) * 1_000_000,
                "job".to_string(),
                "extra".to_string(),
                "nonce".to_string(),
            ),
            SimplePplnsShare::new(
                2,
                400,
                "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string(),
                "worker2".to_string(),
                (current_time - 2400) * 1_000_000,
                "job".to_string(),
                "extra".to_string(),
                "nonce".to_string(),
            ),
        ];

        chain_store_handle
            .expect_get_pplns_shares_filtered()
            .return_const(shares);

        let total_amount = bitcoin::Amount::from_sat(100_000_000); // 1.0 BTC

        let stratum_config = StratumConfig::new_for_test_default().parse().unwrap();

        let result = payout
            .get_output_distribution(&chain_store_handle, 1000.0, total_amount, &stratum_config)
            .unwrap();

        assert_eq!(result.len(), 2);

        // Check total distribution equals input amount
        let total_distributed: bitcoin::Amount = result.iter().map(|op| op.amount).sum();
        assert_eq!(total_distributed, total_amount);

        // Check proportional distribution (60% and 40%)
        // Note: Due to rounding and remainder handling, we check ranges
        let addr1_amount = result
            .iter()
            .find(|op| op.address.to_string() == "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq")
            .unwrap()
            .amount;
        let addr2_amount = result
            .iter()
            .find(|op| op.address.to_string() == "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
            .unwrap()
            .amount;

        // addr1 should get ~60%, addr2 should get ~40%
        assert!(addr1_amount.to_sat() >= 59_000_000 && addr1_amount.to_sat() <= 61_000_000);
        assert!(addr2_amount.to_sat() >= 39_000_000 && addr2_amount.to_sat() <= 41_000_000);
    }

    #[tokio::test]
    async fn test_get_output_distribution_same_address_multiple_shares() {
        let mut payout = Payout::new(86400);
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut chain_store_handle = ChainStoreHandle::default();

        // Multiple shares from same address should be aggregated
        let shares = vec![
            SimplePplnsShare::new(
                1,
                300,
                "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq".to_string(),
                "worker1".to_string(),
                (current_time - 1800) * 1_000_000,
                "job".to_string(),
                "extra".to_string(),
                "nonce".to_string(),
            ),
            SimplePplnsShare::new(
                1,
                200,
                "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq".to_string(),
                "worker2".to_string(),
                (current_time - 2400) * 1_000_000,
                "job20".to_string(),
                "extra20".to_string(),
                "nonce20".to_string(),
            ),
            SimplePplnsShare::new(
                2,
                500,
                "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string(),
                "worker3".to_string(),
                (current_time - 3000) * 1_000_000,
                "job".to_string(),
                "extra".to_string(),
                "nonce".to_string(),
            ),
        ];

        chain_store_handle
            .expect_get_pplns_shares_filtered()
            .return_const(shares);

        let total_amount = bitcoin::Amount::from_sat(100_000_000); // 1.0 BTC

        let stratum_config = StratumConfig::new_for_test_default().parse().unwrap();

        let result = payout
            .get_output_distribution(&chain_store_handle, 1000.0, total_amount, &stratum_config)
            .unwrap();

        // Should have 2 unique addresses
        assert_eq!(result.len(), 2);

        let total_distributed: bitcoin::Amount = result.iter().map(|op| op.amount).sum();
        assert_eq!(total_distributed, total_amount);

        // addr1 has 500 difficulty total (300+200), addr2 has 500 difficulty
        // So should be 50/50 split
        for output in &result {
            assert!(output.amount.to_sat() >= 49_000_000 && output.amount.to_sat() <= 51_000_000);
        }
    }

    #[tokio::test]
    async fn test_get_output_distribution_empty_shares() {
        let mut payout = Payout::new(86400);
        let mut chain_store_handle = ChainStoreHandle::default();

        let total_amount = bitcoin::Amount::from_sat(100_000_000);

        chain_store_handle
            .expect_get_pplns_shares_filtered()
            .return_const(vec![]);

        let stratum_config = StratumConfig::new_for_test_default().parse().unwrap();

        let result = payout
            .get_output_distribution(&chain_store_handle, 1000.0, total_amount, &stratum_config)
            .unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].address, *stratum_config.bootstrap_address());
        assert_eq!(result[0].amount, total_amount);
    }

    #[tokio::test]
    async fn test_get_output_distribution_with_donation() {
        let mut payout = Payout::new(86400);
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut chain_store_handle = ChainStoreHandle::default();

        let shares = vec![
            SimplePplnsShare::new(
                1,
                600,
                "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq".to_string(),
                "worker1".to_string(),
                (current_time - 1800) * 1_000_000,
                "job".to_string(),
                "extra".to_string(),
                "nonce".to_string(),
            ),
            SimplePplnsShare::new(
                2,
                400,
                "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string(),
                "worker2".to_string(),
                (current_time - 2400) * 1_000_000,
                "job".to_string(),
                "extra".to_string(),
                "nonce".to_string(),
            ),
        ];

        chain_store_handle
            .expect_get_pplns_shares_filtered()
            .return_const(shares);

        let total_amount = bitcoin::Amount::from_sat(100_000_000); // 1.0 BTC

        // Create config with 5% donation (500 basis points out of 10000)
        let mut stratum_config = StratumConfig::new_for_test_default();
        stratum_config.donation_address =
            Some("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string());
        stratum_config.donation = Some(500); // 5%
        let stratum_config = stratum_config.parse().unwrap();

        let result = payout
            .get_output_distribution(&chain_store_handle, 1000.0, total_amount, &stratum_config)
            .unwrap();

        // Should have 3 outputs: donation + 2 miners
        assert_eq!(result.len(), 3);

        // Find donation output
        let donation_output = result
            .iter()
            .find(|op| op.address.to_string() == "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx")
            .expect("Donation address not found");

        // Donation should be exactly 5% of total
        let expected_donation = bitcoin::Amount::from_sat(5_000_000); // 5% of 1 BTC
        assert_eq!(donation_output.amount, expected_donation);

        // Total should still equal input
        let total_distributed: bitcoin::Amount = result.iter().map(|op| op.amount).sum();
        assert_eq!(total_distributed, total_amount);

        // Miners should get remaining 95M sats proportionally (60% and 40% of 95M)
        let miner1_output = result
            .iter()
            .find(|op| op.address.to_string() == "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq")
            .unwrap();
        let miner2_output = result
            .iter()
            .find(|op| op.address.to_string() == "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
            .unwrap();

        // Allow small rounding differences
        assert!(
            miner1_output.amount.to_sat() >= 56_900_000
                && miner1_output.amount.to_sat() <= 57_100_000
        );
        assert!(
            miner2_output.amount.to_sat() >= 37_900_000
                && miner2_output.amount.to_sat() <= 38_100_000
        );
    }

    #[tokio::test]
    async fn test_get_output_distribution_with_fee() {
        let mut payout = Payout::new(86400);
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut chain_store_handle = ChainStoreHandle::default();

        let shares = vec![
            SimplePplnsShare::new(
                1,
                600,
                "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq".to_string(),
                "worker1".to_string(),
                (current_time - 1800) * 1_000_000,
                "job".to_string(),
                "extra".to_string(),
                "nonce".to_string(),
            ),
            SimplePplnsShare::new(
                2,
                400,
                "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string(),
                "worker2".to_string(),
                (current_time - 2400) * 1_000_000,
                "job".to_string(),
                "extra".to_string(),
                "nonce".to_string(),
            ),
        ];

        chain_store_handle
            .expect_get_pplns_shares_filtered()
            .return_const(shares);

        let total_amount = bitcoin::Amount::from_sat(100_000_000); // 1.0 BTC

        // Create config with 2% fee
        let mut stratum_config = StratumConfig::new_for_test_default();
        stratum_config.fee_address =
            Some("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7".to_string());
        stratum_config.fee = Some(200); // 2%
        let stratum_config = stratum_config.parse().unwrap();

        let result = payout
            .get_output_distribution(&chain_store_handle, 1000.0, total_amount, &stratum_config)
            .unwrap();

        // Should have 3 outputs: fee + 2 miners
        assert_eq!(result.len(), 3);

        // Find fee output
        let fee_output = result
            .iter()
            .find(|op| {
                op.address.to_string()
                    == "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7"
            })
            .expect("Fee address not found");

        // Fee should be exactly 2% of total
        let expected_fee = bitcoin::Amount::from_sat(2_000_000); // 2% of 1 BTC
        assert_eq!(fee_output.amount, expected_fee);

        // Total should still equal input
        let total_distributed: bitcoin::Amount = result.iter().map(|op| op.amount).sum();
        assert_eq!(total_distributed, total_amount);

        // Miners should get remaining 98M sats proportionally (60% and 40% of 98M)
        let miner1_output = result
            .iter()
            .find(|op| op.address.to_string() == "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq")
            .unwrap();
        let miner2_output = result
            .iter()
            .find(|op| op.address.to_string() == "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
            .unwrap();

        // Allow small rounding differences
        assert!(
            miner1_output.amount.to_sat() >= 58_700_000
                && miner1_output.amount.to_sat() <= 58_900_000
        );
        assert!(
            miner2_output.amount.to_sat() >= 39_100_000
                && miner2_output.amount.to_sat() <= 39_300_000
        );
    }

    #[tokio::test]
    async fn test_get_output_distribution_with_donation_and_fee() {
        let mut payout = Payout::new(86400);
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut chain_store_handle = ChainStoreHandle::default();

        let shares = vec![
            SimplePplnsShare::new(
                1,
                600,
                "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq".to_string(),
                "worker1".to_string(),
                (current_time - 1800) * 1_000_000,
                "job".to_string(),
                "extra".to_string(),
                "nonce".to_string(),
            ),
            SimplePplnsShare::new(
                2,
                400,
                "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string(),
                "worker2".to_string(),
                (current_time - 2400) * 1_000_000,
                "job".to_string(),
                "extra".to_string(),
                "nonce".to_string(),
            ),
        ];

        chain_store_handle
            .expect_get_pplns_shares_filtered()
            .return_const(shares);

        let total_amount = bitcoin::Amount::from_sat(100_000_000); // 1.0 BTC

        // Create config with 5% donation and 2% fee
        let mut stratum_config = StratumConfig::new_for_test_default();
        stratum_config.donation_address =
            Some("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string());
        stratum_config.donation = Some(500); // 5%
        stratum_config.fee_address =
            Some("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7".to_string());
        stratum_config.fee = Some(200); // 2%
        let stratum_config = stratum_config.parse().unwrap();

        let result = payout
            .get_output_distribution(&chain_store_handle, 1000.0, total_amount, &stratum_config)
            .unwrap();

        // Should have 4 outputs: donation + fee + 2 miners
        assert_eq!(result.len(), 4);

        // Find donation output (deducted first)
        let donation_output = result
            .iter()
            .find(|op| op.address.to_string() == "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx")
            .expect("Donation address not found");

        // Donation should be 5% of total = 5M sats
        let expected_donation = bitcoin::Amount::from_sat(5_000_000);
        assert_eq!(donation_output.amount, expected_donation);

        // Find fee output (deducted from remaining after donation)
        let fee_output = result
            .iter()
            .find(|op| {
                op.address.to_string()
                    == "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7"
            })
            .expect("Fee address not found");

        // Fee should be 2% of remaining 95M = 1.9M sats
        let expected_fee = bitcoin::Amount::from_sat(1_900_000);
        assert_eq!(fee_output.amount, expected_fee);

        // Total should still equal input
        let total_distributed: bitcoin::Amount = result.iter().map(|op| op.amount).sum();
        assert_eq!(total_distributed, total_amount);

        // Miners should get remaining 93.1M sats proportionally (60% and 40%)
        let remaining = total_amount - expected_donation - expected_fee;
        assert_eq!(remaining.to_sat(), 93_100_000);

        let miner1_output = result
            .iter()
            .find(|op| op.address.to_string() == "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq")
            .unwrap();
        let miner2_output = result
            .iter()
            .find(|op| op.address.to_string() == "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
            .unwrap();

        // 60% of 93.1M ≈ 55.86M, 40% ≈ 37.24M (with rounding)
        assert!(
            miner1_output.amount.to_sat() >= 55_700_000
                && miner1_output.amount.to_sat() <= 56_000_000
        );
        assert!(
            miner2_output.amount.to_sat() >= 37_100_000
                && miner2_output.amount.to_sat() <= 37_400_000
        );
    }

    #[tokio::test]
    async fn test_get_output_distribution_with_donation_empty_shares() {
        let mut payout = Payout::new(86400);
        let mut chain_store_handle = ChainStoreHandle::default();

        chain_store_handle
            .expect_get_pplns_shares_filtered()
            .return_const(vec![]);

        let total_amount = bitcoin::Amount::from_sat(100_000_000); // 1.0 BTC

        // Create config with donation
        let mut stratum_config = StratumConfig::new_for_test_default();
        stratum_config.donation_address =
            Some("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string());
        stratum_config.donation = Some(500); // 5%
        let stratum_config = stratum_config.parse().unwrap();

        let result = payout
            .get_output_distribution(&chain_store_handle, 1000.0, total_amount, &stratum_config)
            .unwrap();

        // When no shares, all funds should go to bootstrap address (not donation)
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].address, *stratum_config.bootstrap_address());
        assert_eq!(result[0].amount, total_amount);
    }

    #[tokio::test]
    async fn test_get_output_distribution_with_zero_donation() {
        let mut payout = Payout::new(86400);
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut chain_store_handle = ChainStoreHandle::default();

        let shares = vec![
            SimplePplnsShare::new(
                1,
                600,
                "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq".to_string(),
                "worker1".to_string(),
                (current_time - 1800) * 1_000_000,
                "job".to_string(),
                "extra".to_string(),
                "nonce".to_string(),
            ),
            SimplePplnsShare::new(
                2,
                400,
                "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string(),
                "worker2".to_string(),
                (current_time - 2400) * 1_000_000,
                "job".to_string(),
                "extra".to_string(),
                "nonce".to_string(),
            ),
        ];

        chain_store_handle
            .expect_get_pplns_shares_filtered()
            .return_const(shares);

        let total_amount = bitcoin::Amount::from_sat(100_000_000); // 1.0 BTC

        // Create config with 0% donation (should be filtered out)
        let mut stratum_config = StratumConfig::new_for_test_default();
        stratum_config.donation_address =
            Some("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string());
        stratum_config.donation = Some(0); // 0% - should not create output
        let stratum_config = stratum_config.parse().unwrap();

        let result = payout
            .get_output_distribution(&chain_store_handle, 1000.0, total_amount, &stratum_config)
            .unwrap();

        // Should have only 2 outputs: just the 2 miners (no donation output)
        assert_eq!(result.len(), 2);

        // Verify no donation address in outputs
        assert!(
            result
                .iter()
                .all(|op| op.address.to_string() != "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx")
        );

        // Total should still equal input
        let total_distributed: bitcoin::Amount = result.iter().map(|op| op.amount).sum();
        assert_eq!(total_distributed, total_amount);

        // Miners should get full 100M sats proportionally (60% and 40%)
        let miner1_output = result
            .iter()
            .find(|op| op.address.to_string() == "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq")
            .unwrap();
        let miner2_output = result
            .iter()
            .find(|op| op.address.to_string() == "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
            .unwrap();

        // 60% of 100M = 60M, 40% of 100M = 40M
        assert!(
            miner1_output.amount.to_sat() >= 59_900_000
                && miner1_output.amount.to_sat() <= 60_100_000
        );
        assert!(
            miner2_output.amount.to_sat() >= 39_900_000
                && miner2_output.amount.to_sat() <= 40_100_000
        );
    }

    #[tokio::test]
    async fn test_get_output_distribution_with_zero_fee() {
        let mut payout = Payout::new(86400);
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut chain_store_handle = ChainStoreHandle::default();

        let shares = vec![
            SimplePplnsShare::new(
                1,
                600,
                "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq".to_string(),
                "worker1".to_string(),
                (current_time - 1800) * 1_000_000,
                "job".to_string(),
                "extra".to_string(),
                "nonce".to_string(),
            ),
            SimplePplnsShare::new(
                2,
                400,
                "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string(),
                "worker2".to_string(),
                (current_time - 2400) * 1_000_000,
                "job".to_string(),
                "extra".to_string(),
                "nonce".to_string(),
            ),
        ];

        chain_store_handle
            .expect_get_pplns_shares_filtered()
            .return_const(shares);

        let total_amount = bitcoin::Amount::from_sat(100_000_000); // 1.0 BTC

        // Create config with 0% fee (should be filtered out)
        let mut stratum_config = StratumConfig::new_for_test_default();
        stratum_config.fee_address =
            Some("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7".to_string());
        stratum_config.fee = Some(0); // 0% - should not create output
        let stratum_config = stratum_config.parse().unwrap();

        let result = payout
            .get_output_distribution(&chain_store_handle, 1000.0, total_amount, &stratum_config)
            .unwrap();

        // Should have only 2 outputs: just the 2 miners (no fee output)
        assert_eq!(result.len(), 2);

        // Verify no fee address in outputs
        assert!(result.iter().all(|op| op.address.to_string()
            != "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7"));

        // Total should still equal input
        let total_distributed: bitcoin::Amount = result.iter().map(|op| op.amount).sum();
        assert_eq!(total_distributed, total_amount);
    }

    #[tokio::test]
    async fn test_get_output_distribution_with_full_donation_and_invalid_miner_addresses() {
        // This test verifies that when donation is 100%, we don't try to parse miner addresses
        // which allows non-standard usernames when validate_address is false
        let mut payout = Payout::new(86400);
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut chain_store_handle = ChainStoreHandle::default();

        // Create shares with invalid bitcoin addresses (non-standard usernames)
        let shares = vec![
            SimplePplnsShare::new(
                1,
                600,
                "invalid_username_not_a_btc_address".to_string(),
                "worker1".to_string(),
                (current_time - 1800) * 1_000_000,
                "job".to_string(),
                "extra".to_string(),
                "nonce".to_string(),
            ),
            SimplePplnsShare::new(
                2,
                400,
                "another_invalid_name".to_string(),
                "worker2".to_string(),
                (current_time - 2400) * 1_000_000,
                "job".to_string(),
                "extra".to_string(),
                "nonce".to_string(),
            ),
        ];

        chain_store_handle
            .expect_get_pplns_shares_filtered()
            .return_const(shares);

        let total_amount = bitcoin::Amount::from_sat(100_000_000); // 1.0 BTC

        // Create config with 100% donation (10000 basis points)
        let mut stratum_config = StratumConfig::new_for_test_default();
        stratum_config.donation_address =
            Some("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string());
        stratum_config.donation = Some(10000); // 100%
        let stratum_config = stratum_config.parse().unwrap();

        let result = payout
            .get_output_distribution(&chain_store_handle, 1000.0, total_amount, &stratum_config)
            .unwrap();

        // Should have only 1 output: donation gets 100%
        assert_eq!(result.len(), 1);

        // Verify donation address gets all funds
        assert_eq!(
            result[0].address.to_string(),
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"
        );
        assert_eq!(result[0].amount, total_amount);
    }
}
