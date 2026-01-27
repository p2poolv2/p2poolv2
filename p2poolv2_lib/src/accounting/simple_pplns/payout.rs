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

use crate::accounting::OutputPair;
use crate::accounting::simple_pplns::SimplePplnsShare;
use crate::config::StratumConfig;
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

impl Payout {
    /// Creates a new Payout with specified step size.
    ///
    /// # Arguments
    /// * `step_size_seconds` - Batch size in seconds for querying shares from
    ///   Default: 86400 (1 day) for typical pool configurations
    pub fn new(step_size_seconds: u64) -> Self {
        Self { step_size_seconds }
    }

    /// Get shares from chain starting from the latest, going back in time until
    /// the total difficulty is reached. Uses optimized batch querying to avoid
    /// sequential single-share queries.
    ///
    /// # Arguments
    /// * `store` - Handle to the chain store for querying PPLNS shares
    /// * `total_difficulty` - Target cumulative difficulty to collect shares for
    ///
    /// # Returns
    /// Vector of shares ordered from newest to oldest that sum up to at least total_difficulty
    ///
    /// # Implementation
    /// Queries shares in time windows going backwards from the latest timestamp.
    /// Uses the configured step_size_seconds to determine batch size, defaulting to 1 day.
    /// Continues querying additional time windows if total difficulty hasn't been reached.
    async fn get_shares_for_difficulty(
        &self,
        store: &ChainStoreHandle,
        total_difficulty: f64,
    ) -> Result<Vec<SimplePplnsShare>, Box<dyn Error + Send + Sync>> {
        let mut result_shares = Vec::new();
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
                // Process shares from newest to oldest within this batch
                for share in batch_shares.into_iter() {
                    if accumulated_difficulty < total_difficulty {
                        accumulated_difficulty += share.difficulty as f64;
                        result_shares.push(share);
                    }
                }

                // Move to the next time window (further back in time) if total diff not reached
                if accumulated_difficulty < total_difficulty {
                    end_time = start_time;
                }
            }
        }

        Ok(result_shares)
    }

    /// Generate output distribution based on PPLNS shares weighted by difficulty.
    ///
    /// # Arguments
    /// * `store` - Handle to the chain store for querying PPLNS shares
    /// * `total_difficulty` - Target cumulative difficulty to collect shares for
    /// * `total_amount` - Total bitcoin amount to distribute among contributors
    ///
    /// # Returns
    /// Vector of OutputPair containing addresses and their proportional amounts
    pub async fn get_output_distribution(
        &self,
        chain_store_handle: &ChainStoreHandle,
        total_difficulty: f64,
        total_amount: bitcoin::Amount,
        config: &StratumConfig<crate::config::Parsed>,
    ) -> Result<Vec<OutputPair>, Box<dyn Error + Send + Sync>> {
        // Extra two places for potential cuts
        let mut distribution = Vec::<OutputPair>::new();
        let remaining_total_amount = Self::include_address_and_cut(
            &mut distribution,
            total_amount,
            &config.donation_address_parsed,
            config.donation,
        );
        let remaining_total_amount = Self::include_address_and_cut(
            &mut distribution,
            remaining_total_amount,
            &config.fee_address_parsed,
            config.fee,
        );

        // Only calculate proportional distribution if there's remaining amount for miners
        // This avoids parsing miner addresses when 100% goes to donation/fee
        // This also avoids running PPLNS share look ups when we don't need to use that data
        if remaining_total_amount > bitcoin::Amount::ZERO {
            let shares = self
                .get_shares_for_difficulty(&chain_store_handle, total_difficulty)
                .await?;

            if shares.is_empty() {
                return Ok(vec![OutputPair {
                    address: config.bootstrap_address().clone(),
                    amount: total_amount,
                }]);
            }

            let address_difficulty_map = Self::group_shares_by_address(&shares);

            distribution.reserve(address_difficulty_map.len());

            Self::append_proportional_distribution(
                address_difficulty_map,
                remaining_total_amount,
                &mut distribution,
            )?;
        }

        Ok(distribution)
    }

    /// Appends new output pair to distribution and returns remaining amount
    fn include_address_and_cut(
        distribution: &mut Vec<OutputPair>,
        total_amount: bitcoin::Amount,
        address: &Option<Address>,
        cut: Option<u16>, // in basis points
    ) -> Amount {
        const BASIS_POINT_FACTOR: u64 = 10_000; // 100 * 100
        if let (Some(addr), Some(cut_bp)) = (address.as_ref(), cut.filter(|c| *c > 0)) {
            if let Some(amount) = total_amount.checked_mul(cut_bp.into()) {
                if let Some(div_amount) = amount.checked_div(BASIS_POINT_FACTOR) {
                    distribution.push(OutputPair {
                        address: addr.clone(),
                        amount: div_amount,
                    });
                    return total_amount - div_amount;
                } else {
                    tracing::warn!("checked_div failed for amount: {amount:?}");
                }
            } else {
                tracing::warn!(
                    "checked_mul failed for total_amount: {total_amount:?}, cut_bp: {cut_bp:?}"
                );
            }
        }
        total_amount
    }

    /// Groups shares by bitcoin address and sums their difficulties.
    fn group_shares_by_address(shares: &[SimplePplnsShare]) -> HashMap<String, u64> {
        let mut address_difficulty_map = HashMap::new();
        for share in shares {
            if let Some(btcaddress) = &share.btcaddress {
                *address_difficulty_map
                    .entry(btcaddress.clone())
                    .or_insert(0) += share.difficulty;
            }
        }
        address_difficulty_map
    }

    /// Appends proportional distribution of amount based on difficulty weights to the distribtuion
    fn append_proportional_distribution(
        address_difficulty_map: HashMap<String, u64>,
        total_amount: bitcoin::Amount,
        distribution: &mut Vec<OutputPair>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let total_difficulty: u64 = address_difficulty_map.values().sum();
        let mut distributed_amount = bitcoin::Amount::ZERO;

        for (i, (address_str, difficulty)) in address_difficulty_map.iter().enumerate() {
            let address = address_str
                .parse::<bitcoin::Address<_>>()
                .map_err(|e| format!("Invalid bitcoin address '{address_str}': {e}"))?
                .assume_checked();

            let amount = if i == address_difficulty_map.len() - 1 {
                // Last address gets remainder to handle rounding
                total_amount - distributed_amount
            } else {
                let proportion = *difficulty as f64 / total_difficulty as f64;
                let amount_sats = (total_amount.to_sat() as f64 * proportion).round() as u64;
                bitcoin::Amount::from_sat(amount_sats)
            };

            distributed_amount += amount;
            distribution.push(OutputPair { address, amount });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_get_shares_for_difficulty_exact_match() {
        let payout = Payout::new(86400);
        let mut chain_store_handle = ChainStoreHandle::default();

        // Get current time and create recent timestamps (within last hour)
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Create shares with total difficulty of 1000
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
            ), // 30 min ago
            SimplePplnsShare::new(
                2,
                300,
                "addr2".to_string(),
                "worker2".to_string(),
                (current_time - 2400) * 1_000_000,
                "job".to_string(),
                "extra".to_string(),
                "nonce".to_string(),
            ), // 40 min ago
            SimplePplnsShare::new(
                3,
                200,
                "addr3".to_string(),
                "worker3".to_string(),
                (current_time - 3000) * 1_000_000,
                "job".to_string(),
                "extra".to_string(),
                "nonce".to_string(),
            ), // 50 min ago
            SimplePplnsShare::new(
                4,
                100,
                "addr4".to_string(),
                "worker4".to_string(),
                (current_time - 3600) * 1_000_000,
                "job".to_string(),
                "extra".to_string(),
                "nonce".to_string(),
            ), // 60 min ago
        ];

        chain_store_handle
            .expect_get_pplns_shares_filtered()
            .return_const(shares);

        let result = payout
            .get_shares_for_difficulty(&chain_store_handle, 1000.0)
            .await
            .unwrap();

        // Should return all shares since total difficulty is exactly 1000
        assert_eq!(result.len(), 4);

        // Verify shares are in newest-to-oldest order
        assert_eq!(result[0].n_time, (current_time - 1800) * 1_000_000); // 30 min ago
        assert_eq!(result[1].n_time, (current_time - 2400) * 1_000_000); // 40 min ago
        assert_eq!(result[2].n_time, (current_time - 3000) * 1_000_000); // 50 min ago
        assert_eq!(result[3].n_time, (current_time - 3600) * 1_000_000); // 60 min ago

        // Verify total difficulty
        let total: u64 = result.iter().map(|s| s.difficulty).sum();
        assert_eq!(total, 1000);
    }

    #[tokio::test]
    async fn test_get_shares_for_difficulty_partial_match() {
        let payout = Payout::new(86400);
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut chain_store_handle = ChainStoreHandle::default();

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
            .get_shares_for_difficulty(&chain_store_handle, 750.0)
            .await
            .unwrap();

        // Should return first 3 shares (400 + 300 + 200 = 900, which exceeds 750)
        assert_eq!(result.len(), 3);
        assert_eq!(result[0].difficulty, 400);
        assert_eq!(result[1].difficulty, 300);
        assert_eq!(result[2].difficulty, 200);

        let total: u64 = result.iter().map(|s| s.difficulty).sum();
        assert_eq!(total, 900);
    }

    #[tokio::test]
    async fn test_get_shares_for_difficulty_insufficient_shares() {
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
            .get_shares_for_difficulty(&chain_store_handle, 500.0)
            .await
            .unwrap();

        // Should return all available shares even though total difficulty (300) < target (500)
        assert_eq!(result.len(), 2);

        let total: u64 = result.iter().map(|s| s.difficulty).sum();
        assert_eq!(total, 300);
    }

    #[tokio::test]
    async fn test_get_shares_for_difficulty_empty_store() {
        let payout = Payout::new(86400);
        let mut chain_store_handle = ChainStoreHandle::default();

        chain_store_handle
            .expect_get_pplns_shares_filtered()
            .return_const(vec![]);

        let result = payout
            .get_shares_for_difficulty(&chain_store_handle, 1000.0)
            .await
            .unwrap();

        assert_eq!(result.len(), 0);
    }

    #[tokio::test]
    async fn test_get_shares_for_difficulty_single_share_exceeds_target() {
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
            .get_shares_for_difficulty(&chain_store_handle, 1000.0)
            .await
            .unwrap();

        // Should return the single share even though it exceeds target
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].difficulty, 1500);
    }

    #[tokio::test]
    async fn test_get_shares_for_difficulty_multiple_batches() {
        // Test with a small step size to force multiple batch queries
        let payout = Payout::new(100); // 100 second step size
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut chain_store_handle = ChainStoreHandle::default();

        // Create shares spanning 300 seconds (3 batches)
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
            ), // 50s ago
            SimplePplnsShare::new(
                2,
                200,
                "addr2".to_string(),
                "worker2".to_string(),
                (current_time - 150) * 1_000_000,
                "job".to_string(),
                "extra".to_string(),
                "nonce".to_string(),
            ), // 150s ago
            SimplePplnsShare::new(
                3,
                300,
                "addr3".to_string(),
                "worker3".to_string(),
                (current_time - 250) * 1_000_000,
                "job".to_string(),
                "extra".to_string(),
                "nonce".to_string(),
            ), // 250s ago
            SimplePplnsShare::new(
                4,
                400,
                "addr4".to_string(),
                "worker4".to_string(),
                (current_time - 350) * 1_000_000,
                "job".to_string(),
                "extra".to_string(),
                "nonce".to_string(),
            ), // 350s ago
        ];

        let mut seq = mockall::Sequence::new();

        chain_store_handle
            .expect_get_pplns_shares_filtered()
            .times(1)
            .in_sequence(&mut seq)
            .return_const(Vec::from_iter(shares[0..3].iter().cloned()));
        // store
        //     .expect_get_pplns_shares_filtered()
        //     .times(1)
        //     .in_sequence(&mut seq)
        //     .return_const(Vec::from_iter(shares[3..].iter().cloned()));

        let result = payout
            .get_shares_for_difficulty(&chain_store_handle, 550.0)
            .await
            .unwrap();

        // Should return first 3 shares (100 + 200 + 300 = 600, which exceeds 550)
        assert_eq!(result.len(), 3);

        // Verify order (newest first)
        assert_eq!(result[0].n_time, (current_time - 50) * 1_000_000);
        assert_eq!(result[1].n_time, (current_time - 150) * 1_000_000);
        assert_eq!(result[2].n_time, (current_time - 250) * 1_000_000);

        let total: u64 = result.iter().map(|s| s.difficulty).sum();
        assert_eq!(total, 600);
    }

    #[tokio::test]
    async fn test_payout_constructors() {
        let payout1 = Payout::new(3600);
        assert_eq!(payout1.step_size_seconds, 3600);
    }

    #[tokio::test]
    async fn test_get_output_distribution_single_address() {
        let payout = Payout::new(86400);
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
            .await
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
        let payout = Payout::new(86400);
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
            .await
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
        let payout = Payout::new(86400);
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
            .await
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
        let payout = Payout::new(86400);
        let mut chain_store_handle = ChainStoreHandle::default();

        let total_amount = bitcoin::Amount::from_sat(100_000_000);

        chain_store_handle
            .expect_get_pplns_shares_filtered()
            .return_const(vec![]);

        let stratum_config = StratumConfig::new_for_test_default().parse().unwrap();

        let result = payout
            .get_output_distribution(&chain_store_handle, 1000.0, total_amount, &stratum_config)
            .await
            .unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].address, *stratum_config.bootstrap_address());
        assert_eq!(result[0].amount, total_amount);
    }

    #[tokio::test]
    async fn test_group_shares_by_address() {
        let shares = vec![
            SimplePplnsShare::new(
                1,
                100,
                "addr1".to_string(),
                "worker1".to_string(),
                1000,
                "job".to_string(),
                "extra".to_string(),
                "nonce".to_string(),
            ),
            SimplePplnsShare::new(
                2,
                200,
                "addr2".to_string(),
                "worker2".to_string(),
                2000,
                "job".to_string(),
                "extra".to_string(),
                "nonce".to_string(),
            ),
            SimplePplnsShare::new(
                1,
                300,
                "addr1".to_string(),
                "worker3".to_string(),
                3000,
                "job".to_string(),
                "extra".to_string(),
                "nonce".to_string(),
            ),
        ];

        let result = Payout::group_shares_by_address(&shares);

        assert_eq!(result.len(), 2);
        assert_eq!(result.get("addr1"), Some(&400)); // 100 + 300
        assert_eq!(result.get("addr2"), Some(&200));
    }

    #[tokio::test]
    async fn test_create_proportional_distribution() {
        let mut address_difficulty_map = HashMap::new();
        address_difficulty_map.insert(
            "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq".to_string(),
            600,
        );
        address_difficulty_map.insert(
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string(),
            400,
        );

        let total_amount = bitcoin::Amount::from_sat(100_000_000); // 1.0 BTC
        let mut result = Vec::new();
        Payout::append_proportional_distribution(address_difficulty_map, total_amount, &mut result)
            .unwrap();

        assert_eq!(result.len(), 2);

        let total_distributed: bitcoin::Amount = result.iter().map(|op| op.amount).sum();
        assert_eq!(total_distributed, total_amount);

        // Check proportional amounts (60% and 40%)
        let amounts: Vec<_> = result.iter().map(|op| op.amount.to_sat()).collect();
        assert!(amounts.contains(&60_000_000) || amounts.contains(&40_000_000));
    }

    #[tokio::test]
    async fn test_get_output_distribution_with_donation() {
        let payout = Payout::new(86400);
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
            .await
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
        let payout = Payout::new(86400);
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
            .await
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
        let payout = Payout::new(86400);
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
            .await
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
        let payout = Payout::new(86400);
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
            .await
            .unwrap();

        // When no shares, all funds should go to bootstrap address (not donation)
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].address, *stratum_config.bootstrap_address());
        assert_eq!(result[0].amount, total_amount);
    }

    #[tokio::test]
    async fn test_get_output_distribution_with_zero_donation() {
        let payout = Payout::new(86400);
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
            .await
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
        let payout = Payout::new(86400);
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
            .await
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
        let payout = Payout::new(86400);
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
            .await
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
