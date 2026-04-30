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
use crate::node::messages::HandshakeData;
use crate::node::p2p_message_handlers::senders::send_getheaders;
#[cfg(test)]
#[mockall_double::double]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
#[cfg(not(test))]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
use std::error::Error;
use tokio::sync::mpsc;
use tracing::{debug, info};

/// Handle a Handshake message received from a peer.
///
/// Compares the peer's confirmed tip height with our own. If our
/// local chain is behind the peer, sends a getheaders request to
/// begin syncing. Otherwise does nothing.
pub async fn handle_handshake<C: Send + Sync>(
    handshake_data: HandshakeData,
    peer: libp2p::PeerId,
    chain_store_handle: ChainStoreHandle,
    swarm_tx: mpsc::Sender<SwarmSend<C>>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let local_tip_height = match chain_store_handle.get_tip_height() {
        Ok(Some(height)) => height,
        Ok(None) => 0,
        Err(_) => 0,
    };

    info!(
        "Received Handshake from peer {peer}: peer_height={}, local_height={local_tip_height}",
        handshake_data.tip_height
    );

    if local_tip_height < handshake_data.tip_height {
        debug!(
            "Local chain behind peer {peer} ({local_tip_height} < {}), sending getheaders",
            handshake_data.tip_height
        );
        send_getheaders(peer, chain_store_handle, swarm_tx).await?;
    } else {
        debug!(
            "Local chain at or ahead of peer {peer} ({local_tip_height} >= {}), no sync needed",
            handshake_data.tip_height
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::SwarmSend;
    use crate::node::messages::Message;
    use bitcoin::BlockHash;
    use bitcoin::hashes::Hash;
    use std::str::FromStr;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_handle_handshake_local_behind_sends_getheaders() {
        let peer_id = libp2p::PeerId::random();
        let mut chain_store_handle = ChainStoreHandle::default();

        chain_store_handle
            .expect_get_tip_height()
            .times(1)
            .return_once(|| Ok(Some(5)));

        let locator_hash =
            BlockHash::from_str("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5")
                .unwrap();
        chain_store_handle
            .expect_build_locator()
            .times(1)
            .return_once(move || Ok(vec![locator_hash]));

        let (swarm_tx, mut swarm_rx) = mpsc::channel::<SwarmSend<u32>>(10);

        let handshake_data = HandshakeData {
            tip_height: 10,
            tip_hash: BlockHash::all_zeros(),
        };

        let result =
            handle_handshake(handshake_data, peer_id, chain_store_handle, swarm_tx).await;
        assert!(result.is_ok());

        let message = swarm_rx.recv().await.unwrap();
        match message {
            SwarmSend::Request(sent_peer, Message::GetShareHeaders(locator, stop_hash)) => {
                assert_eq!(sent_peer, peer_id);
                assert_eq!(locator, vec![locator_hash]);
                assert_eq!(stop_hash, BlockHash::all_zeros());
            }
            _ => panic!("Expected SwarmSend::Request with GetShareHeaders"),
        }
    }

    #[tokio::test]
    async fn test_handle_handshake_local_ahead_no_message() {
        let peer_id = libp2p::PeerId::random();
        let mut chain_store_handle = ChainStoreHandle::default();

        chain_store_handle
            .expect_get_tip_height()
            .times(1)
            .return_once(|| Ok(Some(10)));

        let (swarm_tx, mut swarm_rx) = mpsc::channel::<SwarmSend<u32>>(10);

        let handshake_data = HandshakeData {
            tip_height: 5,
            tip_hash: BlockHash::all_zeros(),
        };

        let result =
            handle_handshake(handshake_data, peer_id, chain_store_handle, swarm_tx).await;
        assert!(result.is_ok());
        assert!(
            swarm_rx.try_recv().is_err(),
            "No messages should be sent when local is ahead"
        );
    }

    #[tokio::test]
    async fn test_handle_handshake_equal_height_no_message() {
        let peer_id = libp2p::PeerId::random();
        let mut chain_store_handle = ChainStoreHandle::default();

        chain_store_handle
            .expect_get_tip_height()
            .times(1)
            .return_once(|| Ok(Some(10)));

        let (swarm_tx, mut swarm_rx) = mpsc::channel::<SwarmSend<u32>>(10);

        let handshake_data = HandshakeData {
            tip_height: 10,
            tip_hash: BlockHash::all_zeros(),
        };

        let result =
            handle_handshake(handshake_data, peer_id, chain_store_handle, swarm_tx).await;
        assert!(result.is_ok());
        assert!(
            swarm_rx.try_recv().is_err(),
            "No messages should be sent when heights are equal"
        );
    }

    #[tokio::test]
    async fn test_handle_handshake_fresh_node_sends_getheaders() {
        let peer_id = libp2p::PeerId::random();
        let mut chain_store_handle = ChainStoreHandle::default();

        let genesis_hash =
            BlockHash::from_str("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5")
                .unwrap();

        chain_store_handle
            .expect_get_tip_height()
            .times(1)
            .return_once(|| Ok(Some(0)));

        chain_store_handle
            .expect_build_locator()
            .times(1)
            .return_once(move || Ok(vec![genesis_hash]));

        let (swarm_tx, mut swarm_rx) = mpsc::channel::<SwarmSend<u32>>(10);

        let handshake_data = HandshakeData {
            tip_height: 5,
            tip_hash: BlockHash::all_zeros(),
        };

        let result =
            handle_handshake(handshake_data, peer_id, chain_store_handle, swarm_tx).await;
        assert!(result.is_ok());

        let message = swarm_rx.recv().await.unwrap();
        match message {
            SwarmSend::Request(sent_peer, Message::GetShareHeaders(locator, _)) => {
                assert_eq!(sent_peer, peer_id);
                assert_eq!(locator, vec![genesis_hash]);
            }
            _ => panic!("Expected SwarmSend::Request with GetShareHeaders"),
        }
    }
}
