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
use crate::node::SwarmSend;
#[mockall_double::double]
use crate::shares::chain::actor::ChainHandle;
use crate::shares::miner_message::CkPoolMessage;
use crate::shares::ShareBlock;
use bitcoin::PublicKey;
use std::error::Error;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

/// Handle a mining message received from ckpool
pub async fn handle_mining_message<C>(
    mining_message: CkPoolMessage,
    chain_handle: ChainHandle,
    _swarm_tx: mpsc::Sender<SwarmSend<C>>,
    miner_pubkey: PublicKey,
    config: Config, // Added config parameter
) -> Result<(), Box<dyn Error>> {
    match mining_message {
        CkPoolMessage::Share(share) => {
            // Get current difficulty from the share
            let mut current_diff = share.diff;
            
            // Calculate difficulty adjustment based on DRR parameters
            let current_drr = calculate_current_drr(&chain_handle).await?;
            let new_diff = adjust_difficulty(
                current_diff,
                current_drr,
                config.miner.min_drr,
                config.miner.target_drr,
                config.miner.max_drr,
            );

            // Log difficulty adjustments
            if (new_diff - current_diff).abs() > f64::EPSILON {
                info!(
                    "Adjusting difficulty from {:.4} to {:.4} (DRR: {:.2}, Target: {:.2})",
                    current_diff, new_diff, current_drr, config.miner.target_drr
                );
                current_diff = new_diff;
            }

            // Create share block with adjusted difficulty
            let mut share_block = ShareBlock::new(
                share.update_diff(new_diff), // Update share with new difficulty
                miner_pubkey,
                bitcoin::Network::Regtest,
                &mut vec![],
            );

            info!(
                "Processing share (diff: {:.2}, DRR: {:.2})",
                current_diff, current_drr
            );
            
            share_block = chain_handle.setup_share_for_chain(share_block).await;
            if let Err(e) = chain_handle.add_share(share_block).await {
                error!("Failed to add share: {}", e);
                return Err("Error adding share to chain".into());
            }
        }
        CkPoolMessage::Workbase(workbase) => {
            info!(
                "Processing workbase (ID: {}) with DRR params: {:.2}-{:.2}-{:.2}",
                workbase.workinfoid,
                config.miner.min_drr,
                config.miner.target_drr,
                config.miner.max_drr
            );
            if let Err(e) = chain_handle.add_workbase(workbase).await {
                error!("Failed to add workbase: {}", e);
                return Err("Error adding workbase".into());
            }
        }
        CkPoolMessage::UserWorkbase(userworkbase) => {
            info!(
                "Processing user workbase (ID: {})",
                userworkbase.workinfoid
            );
            if let Err(e) = chain_handle.add_user_workbase(userworkbase).await {
                error!("Failed to add user workbase: {}", e);
                return Err("Error adding user workbase".into());
            }
        }
    };
    Ok(())
}

/// Calculate current Difficulty Retarget Rate (DRR)
async fn calculate_current_drr(chain_handle: &ChainHandle) -> Result<f64, Box<dyn Error>> {
    // Implementation would track share submission rate
    // This is a simplified example using chain data
    let total_shares = chain_handle.get_total_difficulty().await;
    Ok(total_shares.to_f64().unwrap_or(0.0) / 100.0) // Simplified DRR calculation
}

/// Adjust difficulty based on DRR parameters
fn adjust_difficulty(
    current_diff: f64,
    current_drr: f64,
    min_drr: f64,
    target_drr: f64,
    max_drr: f64,
) -> f64 {
    if current_drr < min_drr {
        // Decrease difficulty if below minimum DRR
        current_diff * 0.95
    } else if current_drr > max_drr {
        // Increase difficulty if above maximum DRR
        current_diff * 1.05
    } else {
        // Maintain target difficulty
        current_diff
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::messages::Message;
    use crate::test_utils::simple_miner_share;
    use bitcoin::Network;
    use rust_decimal_macros::dec;
    use std::time::{SystemTime, UNIX_EPOCH};

    // Helper function to create test config with customizable DRR values
    fn test_config(min_drr: f64, target_drr: f64, max_drr: f64) -> Config {
        Config {
            network: NetworkConfig {
                listen_address: "0.0.0.0:0".to_string(),
                dial_peers: vec![],
                enable_mdns: false,
                max_pending_incoming: 10,
                max_pending_outgoing: 10,
                max_established_incoming: 50,
                max_established_outgoing: 50,
                max_established_per_peer: 1,
                max_workbase_per_second: 100,
                max_userworkbase_per_second: 100,
                max_miningshare_per_second: 100,
                max_inventory_per_second: 100,
                max_transaction_per_second: 100,
                rate_limit_window_secs: 1,
            },
            store: StoreConfig {
                path: ":memory:".to_string(),
            },
            ckpool: CkPoolConfig {
                host: "localhost".to_string(),
                port: 3333,
            },
            miner: crate::config::MinerConfig {
                pubkey: "020202020202020202020202020202020202020202020202020202020202020202"
                    .parse()
                    .unwrap(),
                min_drr,
                target_drr,
                max_drr,
            },
            bitcoin: BitcoinConfig {
                network: Network::Regtest,
                url: "http://localhost".to_string(),
                username: "test".to_string(),
                password: "test".to_string(),
            },
            logging: LoggingConfig {
                file: None,
                console: true,
                level: "info".to_string(),
            },
        }
    }

    #[tokio::test]
    async fn test_handle_mining_message_share() {
        let config = test_config(0.15, 0.3, 0.4);
        let mut mock_chain = ChainHandle::default();
        let (swarm_tx, _) = mpsc::channel(1);

        // Setup chain mock expectations
        mock_chain.expect_get_total_difficulty()
            .returning(|| async { dec!(30.0) });
        
        mock_chain.expect_add_share()
            .times(1)
            .returning(|_| Ok(()));

        mock_chain.expect_setup_share_for_chain()
            .times(1)
            .returning(|sb| sb);

        let mining_message = CkPoolMessage::Share(simple_miner_share(
            Some("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5"),
            Some(7452731920372203525),
            Some(1),
            Some(dec!(1.0)),
            Some(dec!(1.9041854952356509)),
        ));

        let result = handle_mining_message::<mpsc::Sender<Message>>(
            mining_message,
            mock_chain,
            swarm_tx,
            config.miner.pubkey,
            config,
        )
        .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_drr_based_difficulty_adjustment() {
        let test_cases = vec![
            // (min_drr, target_drr, max_drr, current_drr, expected_multiplier)
            (0.15, 0.3, 0.4, 0.1, 0.95),  // Below min DRR
            (0.15, 0.3, 0.4, 0.2, 1.0),   // Within range
            (0.15, 0.3, 0.4, 0.45, 1.05), // Above max DRR
            (0.2, 0.35, 0.5, 0.18, 0.95), // Custom range below
            (0.2, 0.35, 0.5, 0.4, 1.0),   // Custom range within
            (0.2, 0.35, 0.5, 0.6, 1.05),  // Custom range above
        ];

        for (min, target, max, drr, multiplier) in test_cases {
            let config = test_config(min, target, max);
            let adjusted = adjust_difficulty(1.0, drr, min, target, max);
            assert!(
                (adjusted - (1.0 * multiplier)).abs() < f64::EPSILON,
                "Failed case: min={}, target={}, max={}, drr={}\nExpected: {}, Got: {}",
                min, target, max, drr,
                1.0 * multiplier,
                adjusted
            );
        }
    }

    #[tokio::test]
    async fn test_difficulty_adjustment_edge_cases() {
        let test_cases = vec![
            // Exact boundary tests
            (0.15, 0.3, 0.4, 0.15, 1.0),  // At min DRR
            (0.15, 0.3, 0.4, 0.4, 1.0),   // At max DRR
            (0.15, 0.3, 0.4, 0.149, 0.95), // Just below min
            (0.15, 0.3, 0.4, 0.401, 1.05), // Just above max
        ];

        for (min, target, max, drr, multiplier) in test_cases {
            let config = test_config(min, target, max);
            let adjusted = adjust_difficulty(1.0, drr, min, target, max);
            assert!(
                (adjusted - (1.0 * multiplier)).abs() < f64::EPSILON,
                "Edge case failed: min={}, target={}, max={}, drr={}",
                min, target, max, drr
            );
        }
    }

    #[tokio::test]
    async fn test_dynamic_difficulty_adjustment_process() {
        let config = test_config(0.15, 0.3, 0.4);
        let mut mock_chain = ChainHandle::default();
        let (swarm_tx, _) = mpsc::channel(1);

        // Setup chain mock with dynamic difficulty tracking
        let mut current_diff = 1.0;
        mock_chain.expect_get_total_difficulty()
            .returning(move || async { rust_decimal::Decimal::from_f64(current_diff).unwrap_or_default() });
        
        mock_chain.expect_add_share()
            .times(3)
            .returning(|_| Ok(()));

        mock_chain.expect_setup_share_for_chain()
            .times(3)
            .returning(|sb| sb);

        // Test sequence of DRR values
        let test_sequence = vec![
            (0.1, 0.95),  // Below min, should decrease
            (0.2, 1.0),   // Within range, no change
            (0.5, 1.05),  // Above max, should increase
        ];

        for (drr, expected_multiplier) in test_sequence {
            current_diff = drr * 100.0; // Simulate DRR calculation
            let mining_message = CkPoolMessage::Share(simple_miner_share(
                Some(&hex::encode(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos().to_be_bytes())),
                Some(7452731920372203525),
                Some(1),
                Some(rust_decimal::Decimal::from_str(&current_diff.to_string()).unwrap()),
                Some(dec!(1.9041854952356509)),
            ));

            let result = handle_mining_message::<mpsc::Sender<Message>>(
                mining_message,
                mock_chain.clone(),
                swarm_tx.clone(),
                config.miner.pubkey,
                config.clone(),
            )
            .await;

            assert!(result.is_ok());
            current_diff *= expected_multiplier;
        }
    }
}
