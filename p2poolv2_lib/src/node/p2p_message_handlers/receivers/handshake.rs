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
use crate::node::messages::{HandshakeData, Message};
use crate::node::p2p_message_handlers::senders::send_getheaders;
#[cfg(test)]
#[mockall_double::double]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
#[cfg(not(test))]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
use std::error::Error;
use tokio::sync::mpsc;
use tracing::{debug, error, info};

/// Handle a Handshake message received from a peer.
///
/// Sends an Ack response on the request-response channel, then
/// compares the peer's confirmed tip height and hash with our own.
/// Sends a getheaders request if our local chain is behind the peer,
/// or if both are at the same height but on different tips (fork).
/// Does nothing when the local chain is ahead or already agrees.
pub async fn handle_handshake<C: Send + Sync>(
    handshake_data: HandshakeData,
    peer: libp2p::PeerId,
    chain_store_handle: ChainStoreHandle,
    response_channel: C,
    swarm_tx: mpsc::Sender<SwarmSend<C>>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    if let Err(err) = swarm_tx
        .send(SwarmSend::Response(response_channel, Message::Ack))
        .await
    {
        error!("Failed to send handshake ack: {}", err);
        return Err(format!("Failed to send handshake ack: {err}").into());
    }

    let local_tip_height = chain_store_handle
        .get_tip_height()
        .map_err(|error| {
            error!("Failed to read tip height from store: {error}");
            error
        })?
        .unwrap_or(0);

    let local_tip_hash = chain_store_handle.get_chain_tip().map_err(|error| {
        error!("Failed to read chain tip from store: {error}");
        error
    })?;

    info!(
        "Received Handshake from peer {peer}: peer_height={}, peer_hash={}, local_height={local_tip_height}, local_hash={local_tip_hash}",
        handshake_data.tip_height, handshake_data.tip_hash
    );

    let needs_sync = if local_tip_height < handshake_data.tip_height {
        debug!(
            "Local chain behind peer {peer} ({local_tip_height} < {}), sending getheaders",
            handshake_data.tip_height
        );
        true
    } else if local_tip_height == handshake_data.tip_height
        && local_tip_hash != handshake_data.tip_hash
    {
        debug!(
            "Same height but different tip hash with peer {peer} (local={local_tip_hash}, peer={}), sending getheaders to resolve fork",
            handshake_data.tip_hash
        );
        true
    } else {
        debug!(
            "Local chain at or ahead of peer {peer} ({local_tip_height} >= {}), no sync needed",
            handshake_data.tip_height
        );
        false
    };

    if needs_sync {
        send_getheaders(peer, chain_store_handle, swarm_tx, 0).await?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::SwarmSend;
    use crate::node::messages::Message;
    use crate::store::writer::StoreError;
    use bitcoin::BlockHash;
    use bitcoin::hashes::Hash;
    use std::str::FromStr;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_handle_handshake_local_behind_sends_ack_and_getheaders() {
        let peer_id = libp2p::PeerId::random();
        let mut chain_store_handle = ChainStoreHandle::default();

        let local_tip_hash =
            BlockHash::from_str("00000000a3bbe4fd1da16a29dbdaba01cc35d6fc74ee17f794cf3aab94f7aaa0")
                .unwrap();

        chain_store_handle
            .expect_get_tip_height()
            .times(1)
            .return_once(|| Ok(Some(5)));

        chain_store_handle
            .expect_get_chain_tip()
            .times(1)
            .return_once(move || Ok(local_tip_hash));

        let locator_hash =
            BlockHash::from_str("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5")
                .unwrap();
        chain_store_handle
            .expect_build_locator()
            .times(1)
            .return_once(move |_| Ok(vec![locator_hash]));

        let (swarm_tx, mut swarm_rx) = mpsc::channel::<SwarmSend<u32>>(10);
        let response_channel = 1u32;

        let handshake_data = HandshakeData {
            tip_height: 10,
            tip_hash: BlockHash::all_zeros(),
        };

        let result = handle_handshake(
            handshake_data,
            peer_id,
            chain_store_handle,
            response_channel,
            swarm_tx,
        )
        .await;
        assert!(result.is_ok());

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
                assert_eq!(locator, vec![locator_hash]);
                assert_eq!(stop_hash, BlockHash::all_zeros());
            }
            _ => panic!("Expected SwarmSend::Request with GetShareHeaders"),
        }
    }

    #[tokio::test]
    async fn test_handle_handshake_local_ahead_sends_only_ack() {
        let peer_id = libp2p::PeerId::random();
        let mut chain_store_handle = ChainStoreHandle::default();

        let local_tip_hash =
            BlockHash::from_str("00000000a3bbe4fd1da16a29dbdaba01cc35d6fc74ee17f794cf3aab94f7aaa0")
                .unwrap();

        chain_store_handle
            .expect_get_tip_height()
            .times(1)
            .return_once(|| Ok(Some(10)));

        chain_store_handle
            .expect_get_chain_tip()
            .times(1)
            .return_once(move || Ok(local_tip_hash));

        let (swarm_tx, mut swarm_rx) = mpsc::channel::<SwarmSend<u32>>(10);
        let response_channel = 2u32;

        let handshake_data = HandshakeData {
            tip_height: 5,
            tip_hash: BlockHash::all_zeros(),
        };

        let result = handle_handshake(
            handshake_data,
            peer_id,
            chain_store_handle,
            response_channel,
            swarm_tx,
        )
        .await;
        assert!(result.is_ok());

        let ack_message = swarm_rx.recv().await.unwrap();
        match ack_message {
            SwarmSend::Response(channel, Message::Ack) => {
                assert_eq!(channel, 2u32);
            }
            _ => panic!("Expected SwarmSend::Response with Ack"),
        }

        assert!(
            swarm_rx.try_recv().is_err(),
            "No additional messages should be sent when local is ahead"
        );
    }

    #[tokio::test]
    async fn test_handle_handshake_equal_height_same_hash_sends_only_ack() {
        let peer_id = libp2p::PeerId::random();
        let mut chain_store_handle = ChainStoreHandle::default();

        let shared_tip_hash =
            BlockHash::from_str("00000000a3bbe4fd1da16a29dbdaba01cc35d6fc74ee17f794cf3aab94f7aaa0")
                .unwrap();

        chain_store_handle
            .expect_get_tip_height()
            .times(1)
            .return_once(|| Ok(Some(10)));

        chain_store_handle
            .expect_get_chain_tip()
            .times(1)
            .return_once(move || Ok(shared_tip_hash));

        let (swarm_tx, mut swarm_rx) = mpsc::channel::<SwarmSend<u32>>(10);
        let response_channel = 3u32;

        let handshake_data = HandshakeData {
            tip_height: 10,
            tip_hash: shared_tip_hash,
        };

        let result = handle_handshake(
            handshake_data,
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
            "No messages should be sent when heights and hashes are equal"
        );
    }

    #[tokio::test]
    async fn test_handle_handshake_equal_height_different_hash_sends_ack_and_getheaders() {
        let peer_id = libp2p::PeerId::random();
        let mut chain_store_handle = ChainStoreHandle::default();

        let local_tip_hash =
            BlockHash::from_str("00000000a3bbe4fd1da16a29dbdaba01cc35d6fc74ee17f794cf3aab94f7aaa0")
                .unwrap();
        let peer_tip_hash =
            BlockHash::from_str("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5")
                .unwrap();

        chain_store_handle
            .expect_get_tip_height()
            .times(1)
            .return_once(|| Ok(Some(10)));

        chain_store_handle
            .expect_get_chain_tip()
            .times(1)
            .return_once(move || Ok(local_tip_hash));

        let locator_hash = local_tip_hash;
        chain_store_handle
            .expect_build_locator()
            .times(1)
            .return_once(move |_| Ok(vec![locator_hash]));

        let (swarm_tx, mut swarm_rx) = mpsc::channel::<SwarmSend<u32>>(10);
        let response_channel = 5u32;

        let handshake_data = HandshakeData {
            tip_height: 10,
            tip_hash: peer_tip_hash,
        };

        let result = handle_handshake(
            handshake_data,
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
    async fn test_handle_handshake_fresh_node_sends_ack_and_getheaders() {
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
            .expect_get_chain_tip()
            .times(1)
            .return_once(move || Ok(genesis_hash));

        chain_store_handle
            .expect_build_locator()
            .times(1)
            .return_once(move |_| Ok(vec![genesis_hash]));

        let (swarm_tx, mut swarm_rx) = mpsc::channel::<SwarmSend<u32>>(10);
        let response_channel = 4u32;

        let handshake_data = HandshakeData {
            tip_height: 5,
            tip_hash: BlockHash::all_zeros(),
        };

        let result = handle_handshake(
            handshake_data,
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

        let message = swarm_rx.recv().await.unwrap();
        match message {
            SwarmSend::Request(sent_peer, Message::GetShareHeaders(locator, _)) => {
                assert_eq!(sent_peer, peer_id);
                assert_eq!(locator, vec![genesis_hash]);
            }
            _ => panic!("Expected SwarmSend::Request with GetShareHeaders"),
        }
    }

    #[tokio::test]
    async fn test_handle_handshake_tip_height_error_propagates() {
        let peer_id = libp2p::PeerId::random();
        let mut chain_store_handle = ChainStoreHandle::default();

        chain_store_handle
            .expect_get_tip_height()
            .times(1)
            .return_once(|| Err(StoreError::Database("store unavailable".into())));

        let (swarm_tx, mut swarm_rx) = mpsc::channel::<SwarmSend<u32>>(10);
        let response_channel = 6u32;

        let handshake_data = HandshakeData {
            tip_height: 10,
            tip_hash: BlockHash::all_zeros(),
        };

        let result = handle_handshake(
            handshake_data,
            peer_id,
            chain_store_handle,
            response_channel,
            swarm_tx,
        )
        .await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("store unavailable")
        );

        let ack_message = swarm_rx.recv().await.unwrap();
        match ack_message {
            SwarmSend::Response(_, Message::Ack) => {}
            _ => panic!("Expected SwarmSend::Response with Ack"),
        }
    }

    #[tokio::test]
    async fn test_handle_handshake_chain_tip_error_propagates() {
        let peer_id = libp2p::PeerId::random();
        let mut chain_store_handle = ChainStoreHandle::default();

        chain_store_handle
            .expect_get_tip_height()
            .times(1)
            .return_once(|| Ok(Some(10)));

        chain_store_handle
            .expect_get_chain_tip()
            .times(1)
            .return_once(|| Err(StoreError::Database("corrupt tip".into())));

        let (swarm_tx, mut swarm_rx) = mpsc::channel::<SwarmSend<u32>>(10);
        let response_channel = 7u32;

        let handshake_data = HandshakeData {
            tip_height: 10,
            tip_hash: BlockHash::all_zeros(),
        };

        let result = handle_handshake(
            handshake_data,
            peer_id,
            chain_store_handle,
            response_channel,
            swarm_tx,
        )
        .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("corrupt tip"));

        let ack_message = swarm_rx.recv().await.unwrap();
        match ack_message {
            SwarmSend::Response(_, Message::Ack) => {}
            _ => panic!("Expected SwarmSend::Response with Ack"),
        }
    }
}
