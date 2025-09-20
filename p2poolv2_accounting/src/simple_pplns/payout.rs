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

use crate::simple_pplns::SimplePplnsShare;
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
    /// Default: 86400 (1 day) for typical pool configurations
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
    /// Vector of SimplePplnsShare ordered by timestamp (newest first)
    async fn get_pplns_shares_filtered(
        &self,
        limit: usize,
        start_time: Option<u64>,
        end_time: Option<u64>,
    ) -> Result<Vec<SimplePplnsShare>, Box<dyn Error + Send + Sync>>;
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
        async fn get_pplns_shares_filtered(
            &self,
            _limit: usize,
            start_time: Option<u64>,
            end_time: Option<u64>,
        ) -> Result<Vec<SimplePplnsShare>, Box<dyn Error + Send + Sync>> {
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
}
