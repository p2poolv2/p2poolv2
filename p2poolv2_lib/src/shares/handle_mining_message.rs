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

use crate::node::SwarmSend;
#[cfg(test)]
#[mockall_double::double]
use crate::shares::chain::chain_store::ChainStore;
#[cfg(not(test))]
use crate::shares::chain::chain_store::ChainStore;
use crate::shares::share_block::ShareBlock;
use bitcoin::PublicKey;
use std::error::Error;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::error;

/// Handle a mining message received from ckpool
/// For now the message can be a share or a GBT workbase
/// We store the received message in the node's database
/// we assume it is valid and add it to the chain.
pub async fn handle_mining_message<C>(
    share_block: ShareBlock,
    store: Arc<ChainStore>,
    swarm_tx: mpsc::Sender<SwarmSend<C>>,
    _miner_pubkey: PublicKey,
) -> Result<(), Box<dyn Error>> {
    let share_block = store.setup_share_for_chain(share_block);
    let share_block_clone = share_block.clone();
    if let Err(e) = store.add_share(share_block) {
        error!("Failed to add share: {}", e);
        return Err("Error adding share to chain".into());
    }
    //Send INV message to the network
    if let Err(e) = swarm_tx.send(SwarmSend::Inv(share_block_clone)).await {
        error!("Failed to send INV message to swarm: {}", e);
        return Err("Failed to send INV message to swarm".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{node::messages::Message, test_utils::TestShareBlockBuilder};
    use bitcoin::BlockHash;
    use std::{str::FromStr, sync::Arc};

    #[tokio::test]
    async fn test_handle_mining_message_share() {
        let miner_pubkey = "020202020202020202020202020202020202020202020202020202020202020202"
            .parse()
            .unwrap();

        let mut mock_chain = ChainStore::default();
        let (swarm_tx, mut swarm_rx) = mpsc::channel(1);
        // Setup expectations
        mock_chain.expect_add_share().times(1).returning(|_| Ok(()));

        mock_chain
            .expect_setup_share_for_chain()
            .times(1)
            .returning(|share_block| {
                let mut share_block = share_block;
                share_block.header.prev_share_blockhash = BlockHash::from_str(
                    "00000000debd331503c0e5348801a2057d2b8c8b96dcfb075d5a283954846173",
                )
                .unwrap();
                share_block.header.uncles = vec![
                    BlockHash::from_str(
                        "00000000debd331503c0e5348801a2057d2b8c8b96dcfb075d5a283954846172",
                    )
                    .unwrap(),
                ];
                share_block
            });

        let share_block = TestShareBlockBuilder::new()
            .prev_share_blockhash(
                "00000000debd331503c0e5348801a2057d2b8c8b96dcfb075d5a283954846173".to_string(),
            )
            .uncles(vec![
                BlockHash::from_str(
                    "00000000debd331503c0e5348801a2057d2b8c8b96dcfb075d5a283954846172",
                )
                .unwrap(),
            ])
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .diff(1)
            .build();

        let result = handle_mining_message::<mpsc::Sender<Message>>(
            share_block,
            Arc::new(mock_chain),
            swarm_tx,
            miner_pubkey,
        )
        .await;

        assert!(result.is_ok());
        // Check that INV was sent
        if let Some(SwarmSend::Inv(share_block)) = swarm_rx.recv().await {
            tracing::info!("Received INV message with share block: {:?}", share_block);
        } else {
            panic!("Expected INV message to be sent to swarm");
        }
    }

    #[tokio::test]
    async fn test_handle_mining_message_share_add_share_error() {
        let miner_pubkey = "020202020202020202020202020202020202020202020202020202020202020202"
            .parse()
            .unwrap();
        let mut mock_chain = ChainStore::default();
        let (swarm_tx, _swarm_rx) = mpsc::channel(1);
        drop(_swarm_rx); // Drop receiver so if send is called the test will fail

        // Setup expectations
        mock_chain
            .expect_add_share()
            .times(1)
            .returning(|_| Err("Failed to add share".into()));

        mock_chain
            .expect_setup_share_for_chain()
            .times(1)
            .returning(|share_block| {
                let mut share_block = share_block;
                share_block.header.prev_share_blockhash = BlockHash::from_str(
                    "00000000debd331503c0e5348801a2057d2b8c8b96dcfb075d5a283954846173",
                )
                .unwrap();
                share_block.header.uncles = vec![
                    BlockHash::from_str(
                        "00000000debd331503c0e5348801a2057d2b8c8b96dcfb075d5a283954846172",
                    )
                    .unwrap(),
                ];
                share_block
            });

        let share_block = TestShareBlockBuilder::new()
            .prev_share_blockhash(
                "00000000debd331503c0e5348801a2057d2b8c8b96dcfb075d5a283954846173".to_string(),
            )
            .uncles(vec![
                BlockHash::from_str(
                    "00000000debd331503c0e5348801a2057d2b8c8b96dcfb075d5a283954846172",
                )
                .unwrap(),
            ])
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .diff(1)
            .build();

        let result = handle_mining_message::<mpsc::Sender<Message>>(
            share_block,
            Arc::new(mock_chain),
            swarm_tx,
            miner_pubkey,
        )
        .await;

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Error adding share to chain"
        );
    }
    #[tokio::test]
    async fn test_handle_mining_message_share_send_inv_error() {
        let miner_pubkey = "020202020202020202020202020202020202020202020202020202020202020202"
            .parse()
            .unwrap();
        let mut mock_chain = ChainStore::default();
        let (swarm_tx, swarm_rx) = mpsc::channel(1);

        // Close the receiver to simulate a send failure
        drop(swarm_rx);

        // Setup expectations
        mock_chain.expect_add_share().times(1).returning(|_| Ok(()));

        mock_chain
            .expect_setup_share_for_chain()
            .times(1)
            .returning(|share_block| {
                let mut share_block = share_block;
                share_block.header.prev_share_blockhash = BlockHash::from_str(
                    "00000000debd331503c0e5348801a2057d2b8c8b96dcfb075d5a283954846173",
                )
                .unwrap();
                share_block.header.uncles = vec![
                    BlockHash::from_str(
                        "00000000debd331503c0e5348801a2057d2b8c8b96dcfb075d5a283954846172",
                    )
                    .unwrap(),
                ];
                share_block
            });

        let share_block = TestShareBlockBuilder::new()
            .prev_share_blockhash(
                "00000000debd331503c0e5348801a2057d2b8c8b96dcfb075d5a283954846173".to_string(),
            )
            .uncles(vec![
                BlockHash::from_str(
                    "00000000debd331503c0e5348801a2057d2b8c8b96dcfb075d5a283954846172",
                )
                .unwrap(),
            ])
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .diff(1)
            .build();

        let result = handle_mining_message::<mpsc::Sender<Message>>(
            share_block,
            Arc::new(mock_chain),
            swarm_tx,
            miner_pubkey,
        )
        .await;
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Failed to send INV message to swarm"
        );
    }
}
