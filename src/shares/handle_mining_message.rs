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

#[mockall_double::double]
use crate::node::actor::NodeHandle;
use crate::node::messages::Message;
use crate::shares::miner_message::MinerMessage;
use crate::shares::ShareBlock;
use std::error::Error;
use tracing::error;

/// Handle a mining message received from ckpool
/// For now the message can be a share or a GBT workbase
/// We store the received message in the node's database and send a gossip message to the network as this is our local share,
/// we assume it is valid and add it to the chain.
pub async fn handle_mining_message(
    mining_message: MinerMessage,
    node_handle: &NodeHandle,
) -> Result<(), Box<dyn Error>> {
    let message: Message;
    match mining_message {
        MinerMessage::Share(share) => {
            let share_block = ShareBlock::new(share);
            message = Message::ShareBlock(share_block.clone());
            if let Err(e) = node_handle.add_share(share_block).await {
                error!("Failed to add share: {}", e);
                return Err("Error adding share to chain".into());
            }
        }
        MinerMessage::Workbase(workbase) => {
            message = Message::Workbase(workbase.clone());
            if let Err(e) = node_handle.add_workbase(workbase).await {
                error!("Failed to add workbase: {}", e);
                return Err("Error adding workbase".into());
            }
        }
    };

    if let Err(e) = node_handle.send_gossip(message).await {
        error!("Failed to send share: {}", e);
        return Err("Error sending share to network".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[mockall_double::double]
    use crate::node::actor::NodeHandle;
    use crate::test_utils::fixtures::simple_miner_share;
    use rust_decimal_macros::dec;

    #[tokio::test]
    async fn test_handle_mining_message_share() {
        let mut mock_handle = NodeHandle::default();

        // Setup expectations
        mock_handle
            .expect_add_share()
            .times(1)
            .returning(|_| Ok(()));

        mock_handle
            .expect_send_gossip()
            .times(1)
            .returning(|_| Ok(()));

        let mining_message = MinerMessage::Share(simple_miner_share(
            Some(7452731920372203525),
            Some(1),
            Some(dec!(1.0)),
            Some(dec!(1.9041854952356509)),
        ));

        let result = handle_mining_message(mining_message, &mock_handle).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_mining_message_share_send_gossip_error() {
        let mut mock_handle = NodeHandle::default();

        // Setup expectations
        mock_handle
            .expect_add_share()
            .times(1)
            .returning(|_| Ok(()));

        mock_handle
            .expect_send_gossip()
            .times(1)
            .returning(|_| Err("Failed to send gossip".into()));

        let mining_message = MinerMessage::Share(simple_miner_share(
            Some(7452731920372203525),
            Some(1),
            Some(dec!(1.0)),
            Some(dec!(1.9041854952356509)),
        ));

        let result = handle_mining_message(mining_message, &mock_handle).await;

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Error sending share to network"
        );
    }

    #[tokio::test]
    async fn test_handle_mining_message_share_add_share_error() {
        let mut mock_handle = NodeHandle::default();

        // Setup expectations
        mock_handle
            .expect_add_share()
            .times(1)
            .returning(|_| Err("Failed to add share".into()));

        // send_gossip should never be called
        mock_handle.expect_send_gossip().times(0);

        let mining_message = MinerMessage::Share(simple_miner_share(
            Some(7452731920372203525),
            Some(1),
            Some(dec!(1.0)),
            Some(dec!(1.9041854952356509)),
        ));

        let result = handle_mining_message(mining_message, &mock_handle).await;

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Error adding share to chain"
        );
    }
}
