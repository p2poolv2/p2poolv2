// Copyright (C) 2024, 2025 P2Poolv2 Developers (see AUTHORS)
//
//  This file is part of P2Poolv2
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

use crate::config::Config;
use jsonrpsee::core::client::ClientT;
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use rust_decimal::Decimal;
use serde_json::json;
use std::error::Error;
use std::time::Duration;
use tracing::{debug, error};

const TARGET_DRR_MIN: f64 = 0.15; // 15% rejection rate minimum
const TARGET_DRR_MAX: f64 = 0.4;  // 40% rejection rate maximum
const TARGET_DRR_OPTIMAL: f64 = 0.3; // 30% optimal rejection rate
const SHARE_TARGET_TIME: Duration = Duration::from_secs(3); // Target 1 share every 3 seconds

/// Get the current P2Pool network difficulty from the JSON-RPC endpoint
pub async fn get_p2pool_difficulty(config: &Config) -> Result<f64, Box<dyn Error>> {
    let client = HttpClientBuilder::default()
        .build(&format!("http://{}:{}", config.network.listen_address, config.network.port))?;

    let params = vec![];
    let response: f64 = client.request("getnetworkdifficulty", params).await?;
    
    Ok(response)
}

/// Calculate new miner difficulty based on DRR (Difficulty Rejection Rate)
/// 
/// The DRR is calculated as: (rejected_shares) / (total_shares)
/// We want to maintain a DRR between TARGET_DRR_MIN and TARGET_DRR_MAX
/// with TARGET_DRR_OPTIMAL being the ideal target
pub fn calculate_new_difficulty(
    current_diff: f64,
    accepted_shares: u64,
    rejected_shares: u64,
    elapsed_time: Duration
) -> f64 {
    let total_shares = accepted_shares + rejected_shares;
    if total_shares == 0 {
        return current_diff; // No adjustment if no shares
    }

    let current_drr = rejected_shares as f64 / total_shares as f64;
    let shares_per_second = total_shares as f64 / elapsed_time.as_secs_f64();
    let target_shares_per_second = 1.0 / SHARE_TARGET_TIME.as_secs_f64();

    // Adjust difficulty based on both DRR and share rate
    let mut diff_multiplier = 1.0;

    // DRR adjustment
    if current_drr < TARGET_DRR_MIN {
        // Too few rejections, increase difficulty
        diff_multiplier *= 1.2;
    } else if current_drr > TARGET_DRR_MAX {
        // Too many rejections, decrease difficulty
        diff_multiplier *= 0.8;
    }

    // Share rate adjustment
    if shares_per_second > target_shares_per_second * 1.1 {
        // Too many shares, increase difficulty
        diff_multiplier *= 1.1;
    } else if shares_per_second < target_shares_per_second * 0.9 {
        // Too few shares, decrease difficulty
        diff_multiplier *= 0.9;
    }

    let new_diff = current_diff * diff_multiplier;
    debug!(
        "Difficulty adjustment: current_diff={}, drr={:.2}, shares_per_sec={:.2}, new_diff={}",
        current_diff, current_drr, shares_per_second, new_diff
    );

    new_diff
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_new_difficulty() {
        // Test case 1: Optimal DRR and share rate
        let new_diff = calculate_new_difficulty(
            1.0,
            70,
            30,
            Duration::from_secs(300) // 5 minutes
        );
        assert!((new_diff - 1.0).abs() < 0.1); // Should stay roughly the same

        // Test case 2: Too few rejections
        let new_diff = calculate_new_difficulty(
            1.0,
            90,
            10,
            Duration::from_secs(300)
        );
        assert!(new_diff > 1.0); // Should increase difficulty

        // Test case 3: Too many rejections
        let new_diff = calculate_new_difficulty(
            1.0,
            50,
            50,
            Duration::from_secs(300)
        );
        assert!(new_diff < 1.0); // Should decrease difficulty

        // Test case 4: Too many shares per second
        let new_diff = calculate_new_difficulty(
            1.0,
            70,
            30,
            Duration::from_secs(30) // 30 seconds
        );
        assert!(new_diff > 1.0); // Should increase difficulty

        // Test case 5: Too few shares per second
        let new_diff = calculate_new_difficulty(
            1.0,
            70,
            30,
            Duration::from_secs(3000) // 50 minutes
        );
        assert!(new_diff < 1.0); // Should decrease difficulty
    }
} 