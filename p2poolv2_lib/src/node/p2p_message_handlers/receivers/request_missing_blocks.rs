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
use crate::node::p2p_message_handlers::senders::send_getheaders;
#[cfg(test)]
#[mockall_double::double]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
#[cfg(not(test))]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
use bitcoin::BlockHash;
use std::error::Error;
use tokio::sync::mpsc;
use tracing::debug;

/// Check whether any of the given blockhashes are missing from the
/// store and, when the candidate chain is current, send a getheaders
/// request to the peer to sync the missing headers.
///
/// Returns early without sending when the chain is not current
/// (initial sync in progress) or when all blockhashes are already
/// known.
pub async fn request_headers_for_missing_blocks<C>(
    blockhashes: &[BlockHash],
    peer: libp2p::PeerId,
    chain_store_handle: ChainStoreHandle,
    swarm_tx: mpsc::Sender<SwarmSend<C>>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    if !chain_store_handle.is_current() {
        debug!("Chain not current, skipping getheaders for missing blocks from peer {peer}");
        return Ok(());
    }

    let missing_blocks = chain_store_handle.get_missing_blockhashes(blockhashes);
    if missing_blocks.is_empty() {
        return Ok(());
    }

    debug!(
        "Have {} missing blocks from peer {}, sending getheaders",
        missing_blocks.len(),
        peer
    );
    send_getheaders(peer, chain_store_handle, swarm_tx, 0).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::messages::Message;
    use crate::test_utils::TestShareBlockBuilder;
    use bitcoin::hashes::Hash;
    use mockall::predicate::*;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_missing_blocks_and_chain_current_sends_getheaders() {
        let mut chain_store_handle = ChainStoreHandle::default();
        let peer_id = libp2p::PeerId::random();

        let block = TestShareBlockBuilder::new().build();
        let block_hash = block.block_hash();
        let blockhashes = vec![block_hash];
        let missing = vec![block_hash];

        chain_store_handle.expect_is_current().returning(|| true);
        chain_store_handle
            .expect_get_missing_blockhashes()
            .with(eq(blockhashes.clone()))
            .returning(move |_| missing.clone());
        chain_store_handle
            .expect_build_locator()
            .return_once(|_| Ok(vec![BlockHash::all_zeros()]));

        let (swarm_tx, mut swarm_rx) = mpsc::channel::<SwarmSend<()>>(10);

        let result =
            request_headers_for_missing_blocks(&blockhashes, peer_id, chain_store_handle, swarm_tx)
                .await;
        assert!(result.is_ok());

        let message = swarm_rx.recv().await.unwrap();
        match message {
            SwarmSend::Request(sent_peer, Message::GetShareHeaders(locator, stop_hash)) => {
                assert_eq!(sent_peer, peer_id);
                assert_eq!(locator, vec![BlockHash::all_zeros()]);
                assert_eq!(stop_hash, BlockHash::all_zeros());
            }
            _ => panic!("Expected SwarmSend::Request with GetShareHeaders"),
        }
    }

    #[tokio::test]
    async fn test_missing_blocks_chain_not_current_no_getheaders() {
        let mut chain_store_handle = ChainStoreHandle::default();
        let peer_id = libp2p::PeerId::random();

        let block = TestShareBlockBuilder::new().build();
        let block_hash = block.block_hash();
        let blockhashes = vec![block_hash];

        chain_store_handle.expect_is_current().returning(|| false);

        let (swarm_tx, mut swarm_rx) = mpsc::channel::<SwarmSend<()>>(10);

        let result =
            request_headers_for_missing_blocks(&blockhashes, peer_id, chain_store_handle, swarm_tx)
                .await;
        assert!(result.is_ok());

        assert!(
            swarm_rx.try_recv().is_err(),
            "No messages should be sent when chain is not current"
        );
    }

    #[tokio::test]
    async fn test_all_blocks_known_no_getheaders() {
        let mut chain_store_handle = ChainStoreHandle::default();
        let peer_id = libp2p::PeerId::random();

        let block = TestShareBlockBuilder::new().build();
        let block_hash = block.block_hash();
        let blockhashes = vec![block_hash];

        chain_store_handle.expect_is_current().returning(|| true);
        chain_store_handle
            .expect_get_missing_blockhashes()
            .returning(|_| Vec::with_capacity(0));

        let (swarm_tx, mut swarm_rx) = mpsc::channel::<SwarmSend<()>>(10);

        let result =
            request_headers_for_missing_blocks(&blockhashes, peer_id, chain_store_handle, swarm_tx)
                .await;
        assert!(result.is_ok());

        assert!(
            swarm_rx.try_recv().is_err(),
            "No messages should be sent when all blocks are known"
        );
    }
}
