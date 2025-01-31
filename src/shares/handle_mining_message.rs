// Copyright (C) 2024 [Kulpreet Singh]
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

use crate::node::messages::Message;
use crate::node::SwarmSend;
#[mockall_double::double]
use crate::shares::chain::actor::ChainHandle;
use crate::shares::miner_message::CkPoolMessage;
use crate::shares::ShareBlock;
use bitcoin::PublicKey;
use std::error::Error;
use tokio::sync::mpsc;
use tracing::error;

/// Handle a mining message received from ckpool
/// For now the message can be a share or a GBT workbase
/// We store the received message in the node's database and send a gossip message to the network as this is our local share,
/// we assume it is valid and add it to the chain.
pub async fn handle_mining_message(
    mining_message: CkPoolMessage,
    chain_handle: ChainHandle,
    swarm_tx: mpsc::Sender<SwarmSend>,
    miner_pubkey: PublicKey,
) -> Result<(), Box<dyn Error>> {
    let message: Message;
    tracing::info!("Received mining message: {:?}", mining_message);
    match mining_message {
        CkPoolMessage::Share(share) => {
            let mut share_block = ShareBlock::new(share, miner_pubkey);
            share_block.prev_share_blockhash = chain_handle.get_chain_tip().await;
            message = Message::ShareBlock(share_block.clone());
            if let Err(e) = chain_handle.add_share(share_block).await {
                error!("Failed to add share: {}", e);
                return Err("Error adding share to chain".into());
            }
        }
        CkPoolMessage::Workbase(workbase) => {
            message = Message::Workbase(workbase.clone());
            if let Err(e) = chain_handle.add_workbase(workbase).await {
                error!("Failed to add workbase: {}", e);
                return Err("Error adding workbase".into());
            }
        }
    };

    let serialized_message = message.cbor_serialize().unwrap();
    if let Err(e) = swarm_tx.send(SwarmSend::Gossip(serialized_message)).await {
        error!("Failed to send share: {}", e);
        return Err("Error sending share to network".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
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
        mock_chain.expect_get_chain_tip().times(1).returning(|| {
            Some(
                "00000000debd331503c0e5348801a2057d2b8c8b96dcfb075d5a283954846173"
                    .parse()
                    .unwrap(),
            )
        });

        let mining_message = CkPoolMessage::Share(simple_miner_share(
            Some(7452731920372203525),
            Some(1),
            Some(dec!(1.0)),
            Some(dec!(1.9041854952356509)),
        ));

        let result =
            handle_mining_message(mining_message, mock_chain, swarm_tx, miner_pubkey).await;

        assert!(result.is_ok());

        // Verify swarm message was sent
        let swarm_msg = swarm_rx.try_recv().unwrap();
        match swarm_msg {
            SwarmSend::Gossip(_) => (),
            _ => panic!("Expected gossip message"),
        }
    }

    #[tokio::test]
    async fn test_handle_mining_message_share_send_gossip_error() {
        let miner_pubkey = "020202020202020202020202020202020202020202020202020202020202020202"
            .parse()
            .unwrap();
        let mut mock_chain = ChainHandle::default();
        // Create a channel that will be dropped immediately to simulate send error
        let (swarm_tx, _swarm_rx) = mpsc::channel(1);
        drop(_swarm_rx); // Force send error by dropping receiver

        // Setup expectations
        mock_chain.expect_add_share().times(1).returning(|_| Ok(()));
        mock_chain.expect_get_chain_tip().times(1).returning(|| {
            Some(
                "00000000debd331503c0e5348801a2057d2b8c8b96dcfb075d5a283954846173"
                    .parse()
                    .unwrap(),
            )
        });

        let mining_message = CkPoolMessage::Share(simple_miner_share(
            Some(7452731920372203525),
            Some(1),
            Some(dec!(1.0)),
            Some(dec!(1.9041854952356509)),
        ));

        let result =
            handle_mining_message(mining_message, mock_chain, swarm_tx, miner_pubkey).await;

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Error sending share to network"
        );
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
        mock_chain.expect_get_chain_tip().times(1).returning(|| {
            Some(
                "00000000debd331503c0e5348801a2057d2b8c8b96dcfb075d5a283954846173"
                    .parse()
                    .unwrap(),
            )
        });

        let mining_message = CkPoolMessage::Share(simple_miner_share(
            Some(7452731920372203525),
            Some(1),
            Some(dec!(1.0)),
            Some(dec!(1.9041854952356509)),
        ));

        let result =
            handle_mining_message(mining_message, mock_chain, swarm_tx, miner_pubkey).await;

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Error adding share to chain"
        );
    }
}
