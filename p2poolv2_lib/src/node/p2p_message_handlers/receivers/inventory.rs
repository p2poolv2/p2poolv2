// Copyright (C) 2024-2026 P2Poolv2 Developers (see AUTHORS)
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
use crate::node::p2p_message_handlers::senders::send_getheaders;
#[cfg(test)]
#[mockall_double::double]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
#[cfg(not(test))]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
use std::error::Error;
use tokio::sync::mpsc;
use tracing::{debug, error};

/// Handle an Inventory message received from a peer.
///
/// Sends an Ack response on the request-response channel, then
/// when the candidate chain is current, responds to block
/// announcements by sending a getheaders request to sync any missing
/// headers from the announcing peer. The headers-first pipeline then
/// fetches the actual block data.
///
/// When the candidate chain is not current (initial sync in
/// progress), inv messages are ignored because header sync will
/// catch up independently.
pub async fn handle_inventory<C: Send + Sync>(
    inventory: InventoryMessage,
    peer: libp2p::PeerId,
    chain_store_handle: ChainStoreHandle,
    response_channel: C,
    swarm_tx: mpsc::Sender<SwarmSend<C>>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    if let Err(err) = swarm_tx
        .send(SwarmSend::Response(response_channel, Message::Ack))
        .await
    {
        error!("Failed to send inventory ack: {}", err);
        return Err(format!("Failed to send inventory ack: {err}").into());
    }

    debug!("Received Inv: {:?}", inventory);

    match inventory {
        InventoryMessage::BlockHashes(blockhashes) => {
            debug!("Received block hashes locator: {:?}", blockhashes);

            if !chain_store_handle.is_current() {
                debug!("Chain not current, ignoring inv from peer {peer}");
                return Ok(());
            }

            let missing_blocks = chain_store_handle.get_missing_blockhashes(&blockhashes);

            if !missing_blocks.is_empty() {
                debug!(
                    "Have {} missing blocks from peer {}, sending getheaders",
                    missing_blocks.len(),
                    peer
                );
                send_getheaders(peer, chain_store_handle, swarm_tx, 0).await?;
            }
        }
        InventoryMessage::TransactionHashes(transaction_hashes) => {
            debug!(
                "Received transaction hashes inventory: {:?}",
                transaction_hashes
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::ChainStoreHandle;
    use crate::node::messages::InventoryMessage;
    use crate::node::p2p_message_handlers::receivers::inventory::handle_inventory;
    use crate::node::{Message, SwarmSend};
    use crate::test_utils::TestShareBlockBuilder;
    use bitcoin::BlockHash;
    use bitcoin::hashes::Hash;
    use mockall::predicate::*;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_handle_inventory_sends_ack_and_getheaders_when_current() {
        let mut chain_store_handle = ChainStoreHandle::default();
        let peer_id = libp2p::PeerId::random();

        let block1 = TestShareBlockBuilder::new().build();
        let block_hash1: BlockHash = block1.block_hash();

        let blockhashes = vec![block_hash1];
        let missing_blocks = vec![block_hash1];

        chain_store_handle.expect_is_current().returning(|| true);
        chain_store_handle
            .expect_get_missing_blockhashes()
            .with(eq(blockhashes.clone()))
            .returning(move |_| missing_blocks.clone());
        chain_store_handle
            .expect_build_locator()
            .return_once(|_| Ok(vec![BlockHash::all_zeros()]));

        let (swarm_tx, mut swarm_rx) = mpsc::channel::<SwarmSend<u32>>(10);
        let response_channel = 1u32;

        let inventory = InventoryMessage::BlockHashes(blockhashes);
        let result = handle_inventory(
            inventory,
            peer_id,
            chain_store_handle,
            response_channel,
            swarm_tx,
        )
        .await;

        assert!(result.is_ok(), "handle_inventory should return Ok");

        let ack_message = swarm_rx.recv().await.unwrap();
        match ack_message {
            SwarmSend::Response(channel, Message::Ack) => {
                assert_eq!(channel, 1u32);
            }
            _ => panic!("Expected SwarmSend::Response with Ack"),
        }

        let message = swarm_rx.recv().await.unwrap();
        match message {
            SwarmSend::Request(sent_peer, Message::GetShareHeaders(locator, stop_hash)) => {
                assert_eq!(sent_peer, peer_id);
                assert_eq!(locator, vec![BlockHash::all_zeros()]);
                assert_eq!(stop_hash, BlockHash::all_zeros());
            }
            _ => panic!("Expected SwarmSend::Request with GetShareHeaders"),
        }

        assert!(
            swarm_rx.try_recv().is_err(),
            "No more messages should have been sent"
        );
    }

    #[tokio::test]
    async fn test_handle_inventory_sends_ack_when_not_current() {
        let mut chain_store_handle = ChainStoreHandle::default();
        let peer_id = libp2p::PeerId::random();

        let block1 = TestShareBlockBuilder::new().build();
        let block_hash1: BlockHash = block1.block_hash();

        chain_store_handle.expect_is_current().returning(|| false);

        let (swarm_tx, mut swarm_rx) = mpsc::channel::<SwarmSend<u32>>(10);
        let response_channel = 2u32;

        let inventory = InventoryMessage::BlockHashes(vec![block_hash1]);
        let result = handle_inventory(
            inventory,
            peer_id,
            chain_store_handle,
            response_channel,
            swarm_tx,
        )
        .await;

        assert!(result.is_ok());

        let ack_message = swarm_rx.recv().await.unwrap();
        match ack_message {
            SwarmSend::Response(_, Message::Ack) => {}
            _ => panic!("Expected SwarmSend::Response with Ack"),
        }

        assert!(
            swarm_rx.try_recv().is_err(),
            "No additional messages should be sent when chain is not current"
        );
    }

    #[tokio::test]
    async fn test_handle_inventory_sends_ack_when_no_missing_blocks() {
        let mut chain_store_handle = ChainStoreHandle::default();
        let peer_id = libp2p::PeerId::random();

        let block1 = TestShareBlockBuilder::new().build();
        let block_hash1: BlockHash = block1.block_hash();

        chain_store_handle.expect_is_current().returning(|| true);
        chain_store_handle
            .expect_get_missing_blockhashes()
            .returning(|_| Vec::with_capacity(0));

        let (swarm_tx, mut swarm_rx) = mpsc::channel::<SwarmSend<u32>>(10);
        let response_channel = 3u32;

        let inventory = InventoryMessage::BlockHashes(vec![block_hash1]);
        let result = handle_inventory(
            inventory,
            peer_id,
            chain_store_handle,
            response_channel,
            swarm_tx,
        )
        .await;

        assert!(result.is_ok());

        let ack_message = swarm_rx.recv().await.unwrap();
        match ack_message {
            SwarmSend::Response(_, Message::Ack) => {}
            _ => panic!("Expected SwarmSend::Response with Ack"),
        }

        assert!(
            swarm_rx.try_recv().is_err(),
            "No additional messages should be sent when no blocks are missing"
        );
    }

    #[tokio::test]
    async fn test_handle_inventory_transaction_hashes_sends_ack() {
        let chain_store_handle = ChainStoreHandle::default();
        let peer_id = libp2p::PeerId::random();

        let (swarm_tx, mut swarm_rx) = mpsc::channel::<SwarmSend<u32>>(10);
        let response_channel = 4u32;

        let tx_hashes = vec![
            "0000000000000000000000000000000000000000000000000000000000000001"
                .parse()
                .unwrap(),
        ];
        let inventory =
            InventoryMessage::TransactionHashes(crate::shares::share_block::Txids(tx_hashes));
        let result = handle_inventory(
            inventory,
            peer_id,
            chain_store_handle,
            response_channel,
            swarm_tx,
        )
        .await;

        assert!(result.is_ok());

        let ack_message = swarm_rx.recv().await.unwrap();
        match ack_message {
            SwarmSend::Response(_, Message::Ack) => {}
            _ => panic!("Expected SwarmSend::Response with Ack"),
        }

        assert!(
            swarm_rx.try_recv().is_err(),
            "No additional messages should be sent for transaction inventory"
        );
    }
}
