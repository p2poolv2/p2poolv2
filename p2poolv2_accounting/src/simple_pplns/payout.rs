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

use crate::OutputPair;
use crate::simple_pplns::SimplePplnsShare;
use std::collections::HashMap;
use std::error::Error;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct Payout {
    /// PPLNS window is the number of blocks the total work for the PPLNS window should stretch to.
    window_size: usize,

    /// Step size in seconds for batch querying shares from storage.
    /// This determines how far back in time to query in each batch.
    /// Default: 86400 seconds (1 day) for typical pool configurations.
    step_size_seconds: u64,
}

impl Payout {
    /// Creates a new Payout with specified window size and step size.
    ///
    /// # Arguments
    /// * `window_size` - The number of blocks the PPLNS window should stretch to
    /// * `step_size_seconds` - Batch size in seconds for querying shares from
    ///   Default: 86400 (1 day) for typical pool configurations
    pub fn new(window_size: usize, step_size_seconds: u64) -> Self {
        Self {
            window_size,
            step_size_seconds,
        }
    }

    /// Get shares from chain starting from the latest, going back in time until
    /// the total difficulty is reached. Uses optimized batch querying to avoid
    /// sequential single-share queries.
    ///
    /// # Arguments
    /// * `chain_handle` - Handle to the chain store for querying PPLNS shares
    /// * `total_difficulty` - Target cumulative difficulty to collect shares for
    ///
    /// # Returns
    /// Vector of shares ordered from newest to oldest that sum up to at least total_difficulty
    ///
    /// # Implementation
    /// Queries shares in time windows going backwards from the latest timestamp.
    /// Uses the configured step_size_seconds to determine batch size, defaulting to 1 day.
    /// Continues querying additional time windows if total difficulty hasn't been reached.
    pub async fn get_shares_for_difficulty<T>(
        &self,
        chain_handle: &T,
        total_difficulty: u64,
    ) -> Result<Vec<SimplePplnsShare>, Box<dyn Error + Send + Sync>>
    where
        T: PplnsShareProvider,
    {
        let mut result_shares = Vec::new();
        let mut accumulated_difficulty = 0u64;

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
            let batch_shares = chain_handle
                .get_pplns_shares_filtered(usize::MAX, Some(start_time), Some(end_time))
                .await?;

            has_more_shares = !batch_shares.is_empty();

            if has_more_shares {
                // Process shares from newest to oldest within this batch
                for share in batch_shares.into_iter().rev() {
                    if accumulated_difficulty < total_difficulty {
                        accumulated_difficulty += share.difficulty;
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
    /// * `chain_handle` - Handle to the chain store for querying PPLNS shares
    /// * `total_difficulty` - Target cumulative difficulty to collect shares for
    /// * `total_amount` - Total bitcoin amount to distribute among contributors
    ///
    /// # Returns
    /// Vector of OutputPair containing addresses and their proportional amounts
    pub async fn get_output_distribution<T>(
        &self,
        chain_handle: &T,
        total_difficulty: u64,
        total_amount: bitcoin::Amount,
    ) -> Result<Vec<OutputPair>, Box<dyn Error + Send + Sync>>
    where
        T: PplnsShareProvider,
    {
        let shares = self
            .get_shares_for_difficulty(chain_handle, total_difficulty)
            .await?;

        if shares.is_empty() {
            return Ok(Vec::new());
        }

        let address_difficulty_map = Self::group_shares_by_address(&shares);
        let output_pairs =
            Self::create_proportional_distribution(address_difficulty_map, total_amount)?;

        Ok(output_pairs)
    }

    /// Groups shares by bitcoin address and sums their difficulties.
    fn group_shares_by_address(shares: &[SimplePplnsShare]) -> HashMap<String, u64> {
        let mut address_difficulty_map = HashMap::new();
        for share in shares {
            *address_difficulty_map
                .entry(share.btcaddress.clone())
                .or_insert(0) += share.difficulty;
        }
        address_difficulty_map
    }

    /// Creates proportional distribution of amount based on difficulty weights.
    fn create_proportional_distribution(
        address_difficulty_map: HashMap<String, u64>,
        total_amount: bitcoin::Amount,
    ) -> Result<Vec<OutputPair>, Box<dyn Error + Send + Sync>> {
        let total_difficulty: u64 = address_difficulty_map.values().sum();
        let mut output_pairs = Vec::new();
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
            output_pairs.push(OutputPair { address, amount });
        }

        Ok(output_pairs)
    }
}

/// Trait for types that can provide PPLNS shares with time-based filtering.
/// This allows the Payout struct to work with different chain handle implementations.
pub trait PplnsShareProvider {
    /// Get PPLNS shares filtered by time range and limit.
    ///
    /// # Arguments
    /// * `limit` - Maximum number of shares to return
    /// * `start_time` - Optional start time filter (inclusive)
    /// * `end_time` - Optional end time filter (inclusive)
    ///
    /// # Returns
    /// Future that resolves to vector of SimplePplnsShare ordered by timestamp (newest first)
    fn get_pplns_shares_filtered(
        &self,
        limit: usize,
        start_time: Option<u64>,
        end_time: Option<u64>,
    ) -> impl std::future::Future<
        Output = Result<Vec<SimplePplnsShare>, Box<dyn Error + Send + Sync>>,
    > + Send
    + '_;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockPplnsShareProvider {
        shares: Vec<SimplePplnsShare>,
    }

    impl MockPplnsShareProvider {
        fn new(shares: Vec<SimplePplnsShare>) -> Self {
            Self { shares }
        }
    }

    impl PplnsShareProvider for MockPplnsShareProvider {
        fn get_pplns_shares_filtered(
            &self,
            _limit: usize,
            start_time: Option<u64>,
            end_time: Option<u64>,
        ) -> impl std::future::Future<
            Output = Result<Vec<SimplePplnsShare>, Box<dyn Error + Send + Sync>>,
        > + Send
        + '_ {
            async move {
                let filtered_shares: Vec<SimplePplnsShare> = self
                    .shares
                    .iter()
                    .filter(|share| {
                        let timestamp_secs = share.timestamp / 1_000_000;
                        let after_start = start_time.is_none_or(|start| timestamp_secs >= start);
                        let before_end = end_time.is_none_or(|end| timestamp_secs <= end);
                        after_start && before_end
                    })
                    .cloned()
                    .collect();

                // Return shares ordered by timestamp (oldest first, so .rev() in function makes them newest first)
                let mut result = filtered_shares;
                result.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
                Ok(result)
            }
        }
    }

    #[tokio::test]
    async fn test_get_shares_for_difficulty_exact_match() {
        let payout = Payout::new(100, 86400);

        // Get current time and create recent timestamps (within last hour)
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Create shares with total difficulty of 1000
        let shares = vec![
            SimplePplnsShare::new(
                400,
                "addr1".to_string(),
                "worker1".to_string(),
                (current_time - 1800) * 1_000_000,
            ), // 30 min ago
            SimplePplnsShare::new(
                300,
                "addr2".to_string(),
                "worker2".to_string(),
                (current_time - 2400) * 1_000_000,
            ), // 40 min ago
            SimplePplnsShare::new(
                200,
                "addr3".to_string(),
                "worker3".to_string(),
                (current_time - 3000) * 1_000_000,
            ), // 50 min ago
            SimplePplnsShare::new(
                100,
                "addr4".to_string(),
                "worker4".to_string(),
                (current_time - 3600) * 1_000_000,
            ), // 60 min ago
        ];

        let provider = MockPplnsShareProvider::new(shares);
        let result = payout
            .get_shares_for_difficulty(&provider, 1000)
            .await
            .unwrap();

        // Should return all shares since total difficulty is exactly 1000
        assert_eq!(result.len(), 4);

        // Verify shares are in newest-to-oldest order
        assert_eq!(result[0].timestamp, (current_time - 1800) * 1_000_000); // 30 min ago
        assert_eq!(result[1].timestamp, (current_time - 2400) * 1_000_000); // 40 min ago
        assert_eq!(result[2].timestamp, (current_time - 3000) * 1_000_000); // 50 min ago
        assert_eq!(result[3].timestamp, (current_time - 3600) * 1_000_000); // 60 min ago

        // Verify total difficulty
        let total: u64 = result.iter().map(|s| s.difficulty).sum();
        assert_eq!(total, 1000);
    }

    #[tokio::test]
    async fn test_get_shares_for_difficulty_partial_match() {
        let payout = Payout::new(100, 86400);
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let shares = vec![
            SimplePplnsShare::new(
                400,
                "addr1".to_string(),
                "worker1".to_string(),
                (current_time - 1800) * 1_000_000,
            ),
            SimplePplnsShare::new(
                300,
                "addr2".to_string(),
                "worker2".to_string(),
                (current_time - 2400) * 1_000_000,
            ),
            SimplePplnsShare::new(
                200,
                "addr3".to_string(),
                "worker3".to_string(),
                (current_time - 3000) * 1_000_000,
            ),
            SimplePplnsShare::new(
                100,
                "addr4".to_string(),
                "worker4".to_string(),
                (current_time - 3600) * 1_000_000,
            ),
        ];

        let provider = MockPplnsShareProvider::new(shares);
        let result = payout
            .get_shares_for_difficulty(&provider, 750)
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
        let payout = Payout::new(100, 86400);
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let shares = vec![
            SimplePplnsShare::new(
                100,
                "addr1".to_string(),
                "worker1".to_string(),
                (current_time - 1800) * 1_000_000,
            ),
            SimplePplnsShare::new(
                200,
                "addr2".to_string(),
                "worker2".to_string(),
                (current_time - 2400) * 1_000_000,
            ),
        ];

        let provider = MockPplnsShareProvider::new(shares);
        let result = payout
            .get_shares_for_difficulty(&provider, 500)
            .await
            .unwrap();

        // Should return all available shares even though total difficulty (300) < target (500)
        assert_eq!(result.len(), 2);

        let total: u64 = result.iter().map(|s| s.difficulty).sum();
        assert_eq!(total, 300);
    }

    #[tokio::test]
    async fn test_get_shares_for_difficulty_empty_provider() {
        let payout = Payout::new(100, 86400);
        let provider = MockPplnsShareProvider::new(vec![]);

        let result = payout
            .get_shares_for_difficulty(&provider, 1000)
            .await
            .unwrap();

        assert_eq!(result.len(), 0);
    }

    #[tokio::test]
    async fn test_get_shares_for_difficulty_single_share_exceeds_target() {
        let payout = Payout::new(100, 86400);
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let shares = vec![SimplePplnsShare::new(
            1500,
            "addr1".to_string(),
            "worker1".to_string(),
            (current_time - 1800) * 1_000_000,
        )];

        let provider = MockPplnsShareProvider::new(shares);
        let result = payout
            .get_shares_for_difficulty(&provider, 1000)
            .await
            .unwrap();

        // Should return the single share even though it exceeds target
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].difficulty, 1500);
    }

    #[tokio::test]
    async fn test_get_shares_for_difficulty_multiple_batches() {
        // Test with a small step size to force multiple batch queries
        let payout = Payout::new(100, 100); // 100 second step size
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Create shares spanning 300 seconds (3 batches)
        let shares = vec![
            SimplePplnsShare::new(
                100,
                "addr1".to_string(),
                "worker1".to_string(),
                (current_time - 50) * 1_000_000,
            ), // 50s ago
            SimplePplnsShare::new(
                200,
                "addr2".to_string(),
                "worker2".to_string(),
                (current_time - 150) * 1_000_000,
            ), // 150s ago
            SimplePplnsShare::new(
                300,
                "addr3".to_string(),
                "worker3".to_string(),
                (current_time - 250) * 1_000_000,
            ), // 250s ago
            SimplePplnsShare::new(
                400,
                "addr4".to_string(),
                "worker4".to_string(),
                (current_time - 350) * 1_000_000,
            ), // 350s ago
        ];

        let provider = MockPplnsShareProvider::new(shares);
        let result = payout
            .get_shares_for_difficulty(&provider, 550)
            .await
            .unwrap();

        // Should return first 3 shares (100 + 200 + 300 = 600, which exceeds 550)
        assert_eq!(result.len(), 3);

        // Verify order (newest first)
        assert_eq!(result[0].timestamp, (current_time - 50) * 1_000_000);
        assert_eq!(result[1].timestamp, (current_time - 150) * 1_000_000);
        assert_eq!(result[2].timestamp, (current_time - 250) * 1_000_000);

        let total: u64 = result.iter().map(|s| s.difficulty).sum();
        assert_eq!(total, 600);
    }

    #[tokio::test]
    async fn test_payout_constructors() {
        let payout1 = Payout::new(200, 3600);
        assert_eq!(payout1.window_size, 200);
        assert_eq!(payout1.step_size_seconds, 3600);
    }

    #[tokio::test]
    async fn test_get_output_distribution_single_address() {
        let payout = Payout::new(100, 86400);
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let shares = vec![SimplePplnsShare::new(
            1000,
            "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq".to_string(),
            "worker1".to_string(),
            (current_time - 1800) * 1_000_000,
        )];

        let provider = MockPplnsShareProvider::new(shares);
        let total_amount = bitcoin::Amount::from_sat(50_000_000); // 0.5 BTC
        let result = payout
            .get_output_distribution(&provider, 1000, total_amount)
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
        let payout = Payout::new(100, 86400);
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let shares = vec![
            SimplePplnsShare::new(
                600,
                "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq".to_string(),
                "worker1".to_string(),
                (current_time - 1800) * 1_000_000,
            ),
            SimplePplnsShare::new(
                400,
                "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string(),
                "worker2".to_string(),
                (current_time - 2400) * 1_000_000,
            ),
        ];

        let provider = MockPplnsShareProvider::new(shares);
        let total_amount = bitcoin::Amount::from_sat(100_000_000); // 1.0 BTC
        let result = payout
            .get_output_distribution(&provider, 1000, total_amount)
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
        let payout = Payout::new(100, 86400);
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Multiple shares from same address should be aggregated
        let shares = vec![
            SimplePplnsShare::new(
                300,
                "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq".to_string(),
                "worker1".to_string(),
                (current_time - 1800) * 1_000_000,
            ),
            SimplePplnsShare::new(
                200,
                "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq".to_string(),
                "worker2".to_string(),
                (current_time - 2400) * 1_000_000,
            ),
            SimplePplnsShare::new(
                500,
                "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string(),
                "worker3".to_string(),
                (current_time - 3000) * 1_000_000,
            ),
        ];

        let provider = MockPplnsShareProvider::new(shares);
        let total_amount = bitcoin::Amount::from_sat(100_000_000); // 1.0 BTC
        let result = payout
            .get_output_distribution(&provider, 1000, total_amount)
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
        let payout = Payout::new(100, 86400);
        let provider = MockPplnsShareProvider::new(vec![]);
        let total_amount = bitcoin::Amount::from_sat(100_000_000);

        let result = payout
            .get_output_distribution(&provider, 1000, total_amount)
            .await
            .unwrap();

        assert_eq!(result.len(), 0);
    }

    #[tokio::test]
    async fn test_group_shares_by_address() {
        let shares = vec![
            SimplePplnsShare::new(100, "addr1".to_string(), "worker1".to_string(), 1000),
            SimplePplnsShare::new(200, "addr2".to_string(), "worker2".to_string(), 2000),
            SimplePplnsShare::new(300, "addr1".to_string(), "worker3".to_string(), 3000),
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
        let result =
            Payout::create_proportional_distribution(address_difficulty_map, total_amount).unwrap();

        assert_eq!(result.len(), 2);

        let total_distributed: bitcoin::Amount = result.iter().map(|op| op.amount).sum();
        assert_eq!(total_distributed, total_amount);

        // Check proportional amounts (60% and 40%)
        let amounts: Vec<_> = result.iter().map(|op| op.amount.to_sat()).collect();
        assert!(amounts.contains(&60_000_000) || amounts.contains(&40_000_000));
    }
}
