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
use crate::node::messages::{InventoryMessage, Message};
#[cfg(test)]
#[mockall_double::double]
use crate::shares::chain::chain_store::ChainStore;
#[cfg(not(test))]
use crate::shares::chain::chain_store::ChainStore;
use libp2p::PeerId;
use std::error::Error;
use tokio::sync::mpsc;
use tracing::info;

/// Send blocks inventory update to a peer. This is not a response, but is triggered
/// by the node when it has new data to share.
pub async fn send_blocks_inventory<C: 'static>(
    peer_id: PeerId,
    store: std::sync::Arc<ChainStore>,
    swarm_tx: mpsc::Sender<SwarmSend<C>>,
) -> Result<(), Box<dyn Error>> {
    info!("Sending inventory update to peer: {:?}", peer_id);
    let locator = store.build_locator();
    let inventory_message = Message::Inventory(InventoryMessage::BlockHashes(locator));
    swarm_tx
        .send(SwarmSend::Request(peer_id, inventory_message))
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::BlockHash;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_send_blocks_inventory() {
        let mut store = ChainStore::default();
        let (swarm_tx, mut swarm_rx) = mpsc::channel::<SwarmSend<u32>>(1);
        let peer_id = PeerId::random();

        // Mock block hashes that will be returned by build_locator
        let expected_hashes = vec![
            "0000000000000000000000000000000000000000000000000000000000000001"
                .parse::<BlockHash>()
                .unwrap(),
            "0000000000000000000000000000000000000000000000000000000000000002"
                .parse::<BlockHash>()
                .unwrap(),
        ];

        let cloned_expected_hashes = expected_hashes.clone();
        store
            .expect_build_locator()
            .times(1)
            .returning(move || cloned_expected_hashes.clone());

        // Send inventory
        let result = send_blocks_inventory(peer_id, Arc::new(store), swarm_tx).await;
        assert!(result.is_ok());

        // Check the message sent to swarm_tx
        if let Some(SwarmSend::Request(sent_peer_id, sent_message)) = swarm_rx.recv().await {
            assert_eq!(sent_peer_id, peer_id);
            match sent_message {
                Message::Inventory(InventoryMessage::BlockHashes(hashes)) => {
                    assert_eq!(hashes, expected_hashes);
                }
                _ => panic!("Unexpected message type"),
            }
        } else {
            panic!("No message received");
        }
    }
}
