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
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
#[cfg(not(test))]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
use libp2p::PeerId;
use std::error::Error;
use tokio::sync::mpsc;
use tracing::{debug, info};

/// Send blocks inventory update to a peer. This is not a response, but is triggered
/// by the node when it has new data to share.
pub async fn send_block_inventory<C: 'static + Send + Sync>(
    peer_id: PeerId,
    chain_store_handle: ChainStoreHandle,
    swarm_tx: mpsc::Sender<SwarmSend<C>>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    info!("Sending inventory update to peer: {:?}", peer_id);
    let locator = chain_store_handle
        .build_locator()
        .map_err(|e| format!("Failed to build locator {e}"))?;
    let inventory_message = Message::Inventory(InventoryMessage::BlockHashes(locator));
    debug!("Sending request to peer {peer_id}: {inventory_message}");
    swarm_tx
        .send(SwarmSend::Request(peer_id, inventory_message))
        .await
        .map_err(|e| format!("Failed to send inventory: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::writer::StoreError;
    use bitcoin::BlockHash;

    #[tokio::test]
    async fn test_send_blocks_inventory() {
        let mut chain_store_handle = ChainStoreHandle::default();
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
        chain_store_handle
            .expect_build_locator()
            .times(1)
            .returning(move || Ok(cloned_expected_hashes.clone()));

        // Send inventory
        let result = send_block_inventory(peer_id, chain_store_handle, swarm_tx).await;
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

    #[tokio::test]
    async fn test_send_blocks_inventory_locator_error() {
        let mut mock_chain_store = ChainStoreHandle::default();

        mock_chain_store
            .expect_build_locator()
            .returning(|| Err(StoreError::Database("Build locator failed".to_string())));

        let (swarm_tx, _swarm_rx) = mpsc::channel::<SwarmSend<u32>>(1);
        let peer_id = PeerId::random();

        let result = send_block_inventory(peer_id, mock_chain_store, swarm_tx).await;
        assert!(result.is_err());
    }
}
