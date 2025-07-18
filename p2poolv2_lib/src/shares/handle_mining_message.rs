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
use crate::shares::chain::actor::ChainHandle;
#[cfg(not(test))]
use crate::shares::chain::actor::ChainHandle;
use crate::shares::miner_message::CkPoolMessage;
use crate::shares::ShareBlock;
use bitcoin::PublicKey;
use std::error::Error;
use tokio::sync::mpsc;
use tracing::{error, info};

/// Handle a mining message received from ckpool
/// For now the message can be a share or a GBT workbase
/// We store the received message in the node's database
/// we assume it is valid and add it to the chain.
pub async fn handle_mining_message<C>(
    mining_message: CkPoolMessage,
    chain_handle: ChainHandle,
    swarm_tx: mpsc::Sender<SwarmSend<C>>,
    miner_pubkey: PublicKey,
) -> Result<(), Box<dyn Error>> {
    match mining_message {
        CkPoolMessage::Share(share) => {
            let mut share_block =
                ShareBlock::new(share, miner_pubkey, bitcoin::Network::Regtest, &mut vec![]);
            info!(
                "Mining message share block for workinfoid {:?} with hash: {:?}",
                share_block.header.miner_share.workinfoid, share_block.header.miner_share.hash
            );
            share_block = chain_handle.setup_share_for_chain(share_block).await;
            let share_block_clone = share_block.clone();
            if let Err(e) = chain_handle.add_share(share_block).await {
                error!("Failed to add share: {}", e);
                return Err("Error adding share to chain".into());
            }
            //Send INV message to the network
            if let Err(e) = swarm_tx.send(SwarmSend::Inv(share_block_clone)).await {
                error!("Failed to send INV message to swarm: {}", e);
                return Err("Failed to send INV message to swarm".into());
            }
        }
        CkPoolMessage::Workbase(workbase) => {
            info!(
                "Mining message workbase received: {:?}",
                workbase.workinfoid
            );
            if let Err(e) = chain_handle.add_workbase(workbase).await {
                error!("Failed to add workbase: {}", e);
                return Err("Error adding workbase".into());
            }
        }
        CkPoolMessage::UserWorkbase(userworkbase) => {
            info!(
                "Mining message user workbase received: {:?}",
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::messages::Message;
    use crate::test_utils::simple_miner_share;
    use rust_decimal_macros::dec;

    #[tokio::test]
    async fn test_handle_mining_message_share() {
        let miner_pubkey = "020202020202020202020202020202020202020202020202020202020202020202"
            .parse()
            .unwrap();
        let mut mock_chain = ChainHandle::default();
        let (swarm_tx, mut swarm_rx) = mpsc::channel(1);
        // Setup expectations
        mock_chain.expect_add_share().times(1).returning(|_| Ok(()));

        mock_chain
            .expect_setup_share_for_chain()
            .times(1)
            .returning(|share_block| {
                let mut share_block = share_block;
                share_block.header.prev_share_blockhash =
                    Some("00000000debd331503c0e5348801a2057d2b8c8b96dcfb075d5a283954846173".into());
                share_block.header.uncles =
                    vec!["00000000debd331503c0e5348801a2057d2b8c8b96dcfb075d5a283954846172".into()];
                share_block
            });

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
            miner_pubkey,
        )
        .await;

        assert!(result.is_ok());
        // Check that INV was sent
        if let Some(SwarmSend::Inv(share_block)) = swarm_rx.recv().await {
            info!("Received INV message with share block: {:?}", share_block);
        } else {
            panic!("Expected INV message to be sent to swarm");
        }
    }

    #[tokio::test]
    async fn test_handle_mining_message_share_add_share_error() {
        let miner_pubkey = "020202020202020202020202020202020202020202020202020202020202020202"
            .parse()
            .unwrap();
        let mut mock_chain = ChainHandle::default();
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
                share_block.header.prev_share_blockhash =
                    Some("00000000debd331503c0e5348801a2057d2b8c8b96dcfb075d5a283954846173".into());
                share_block.header.uncles =
                    vec!["00000000debd331503c0e5348801a2057d2b8c8b96dcfb075d5a283954846172".into()];
                share_block
            });

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
        let mut mock_chain = ChainHandle::default();
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
                share_block.header.prev_share_blockhash =
                    Some("00000000debd331503c0e5348801a2057d2b8c8b96dcfb075d5a283954846173".into());
                share_block.header.uncles =
                    vec!["00000000debd331503c0e5348801a2057d2b8c8b96dcfb075d5a283954846172".into()];
                share_block
            });

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
