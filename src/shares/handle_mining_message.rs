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
use crate::shares::miner_message::MinerMessage;
use crate::node::messages::Message;
use crate::shares::ShareBlock;
use std::error::Error;
use tracing::error;

/// Handle a mining message received from ckpool
/// For now the message can be a share or a GBT workbase
/// We store the received message in the node's database and send a gossip message to the network as this is our local share,
/// we assume it is valid and add it to the chain.
pub async fn handle_mining_message(mining_message: MinerMessage, node_handle: &NodeHandle) -> Result<(), Box<dyn Error>> {
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
            if let Err(e) = node_handle.store_workbase(workbase).await {
                error!("Failed to store workbase: {}", e);
                return Err("Error storing workbase".into());
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
    use mockall::mock;
    use mockall::predicate::*;
    #[mockall_double::double]
    use crate::node::actor::NodeHandle;
    use crate::shares::ShareBlock;
    use crate::shares::miner_message::MinerShare;

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

        let json = r#"{"workinfoid": 7452731920372203525, "clientid": 1, "enonce1": "336c6d67", "nonce2": "0000000000000000", "nonce": "2eb7b82b", "ntime": "676d6caa", "diff": 1.0, "sdiff": 1.9041854952356509, "hash": "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5", "result": true, "errn": 0, "createdate": "1735224559,536904211", "createby": "code", "createcode": "parse_submit", "createinet": "0.0.0.0:3333", "workername": "tb1q3udk7r26qs32ltf9nmqrjaaa7tr55qmkk30q5d", "username": "tb1q3udk7r26qs32ltf9nmqrjaaa7tr55qmkk30q5d", "address": "172.19.0.4", "agent": "cpuminer/2.5.1"}"#;
        let miner_share: MinerShare = serde_json::from_str(json).unwrap();
        let mining_message = MinerMessage::Share(miner_share);

        let result = handle_mining_message(mining_message, &mock_handle).await;
        
        assert!(result.is_ok());
    }
}

