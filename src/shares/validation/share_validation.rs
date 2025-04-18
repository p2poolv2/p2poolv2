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
use crate::ckpool_integration;
use crate::shares::ShareBlock;
use rust_decimal::Decimal;
use std::error::Error;
use tracing::{debug, error};

/// Validate a share against P2Pool's network difficulty
pub async fn validate_share(
    share: &ShareBlock,
    config: &Config,
) -> Result<bool, Box<dyn Error>> {
    // Get current P2Pool network difficulty
    let network_diff = match ckpool_integration::get_p2pool_difficulty(config).await {
        Ok(diff) => diff,
        Err(e) => {
            error!("Failed to get P2Pool network difficulty: {}", e);
            return Err("Failed to get P2Pool network difficulty".into());
        }
    };

    // Convert share difficulty to f64 for comparison
    let share_diff = match share.header.miner_share.sdiff.to_f64() {
        Some(diff) => diff,
        None => {
            error!("Failed to convert share difficulty to f64");
            return Err("Failed to convert share difficulty to f64".into());
        }
    };

    // Compare share difficulty with network difficulty
    let meets_difficulty = share_diff >= network_diff;
    debug!(
        "Share validation: share_diff={}, network_diff={}, meets_difficulty={}",
        share_diff, network_diff, meets_difficulty
    );

    Ok(meets_difficulty)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rust_decimal_macros::dec;

    #[tokio::test]
    async fn test_validate_share_meets_difficulty() {
        // Create a test config
        let config = Config::load("./config.toml").unwrap();
        
        // Create a share with sufficient difficulty
        let share = ShareBlock::new(
            crate::shares::miner_message::MinerShare {
                workinfoid: 1,
                clientid: 1,
                enonce1: "test".to_string(),
                nonce2: "test".to_string(),
                nonce: "test".to_string(),
                ntime: bitcoin::absolute::Time::from_consensus(1234567890).unwrap(),
                diff: dec!(1.0),
                sdiff: dec!(2.0), // Higher than network diff
                hash: bitcoin::BlockHash::all_zeros(),
                result: true,
                errn: 0,
                createdate: "".to_string(),
                createby: "".to_string(),
                createcode: "".to_string(),
                createinet: "".to_string(),
                workername: "".to_string(),
                username: "".to_string(),
                address: "".to_string(),
                agent: "".to_string(),
            },
            bitcoin::PublicKey::from_str(
                "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
            ).unwrap(),
            bitcoin::Network::Regtest,
            &mut vec![],
        );

        // Mock the network difficulty to be lower than share difficulty
        // This would normally be done through the JSON-RPC endpoint
        // For testing, we assume the network difficulty is 1.0

        let result = validate_share(&share, &config).await;
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[tokio::test]
    async fn test_validate_share_below_difficulty() {
        // Create a test config
        let config = Config::load("./config.toml").unwrap();
        
        // Create a share with insufficient difficulty
        let share = ShareBlock::new(
            crate::shares::miner_message::MinerShare {
                workinfoid: 1,
                clientid: 1,
                enonce1: "test".to_string(),
                nonce2: "test".to_string(),
                nonce: "test".to_string(),
                ntime: bitcoin::absolute::Time::from_consensus(1234567890).unwrap(),
                diff: dec!(1.0),
                sdiff: dec!(0.5), // Lower than network diff
                hash: bitcoin::BlockHash::all_zeros(),
                result: true,
                errn: 0,
                createdate: "".to_string(),
                createby: "".to_string(),
                createcode: "".to_string(),
                createinet: "".to_string(),
                workername: "".to_string(),
                username: "".to_string(),
                address: "".to_string(),
                agent: "".to_string(),
            },
            bitcoin::PublicKey::from_str(
                "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
            ).unwrap(),
            bitcoin::Network::Regtest,
            &mut vec![],
        );

        // Mock the network difficulty to be higher than share difficulty
        // This would normally be done through the JSON-RPC endpoint
        // For testing, we assume the network difficulty is 1.0

        let result = validate_share(&share, &config).await;
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }
} 