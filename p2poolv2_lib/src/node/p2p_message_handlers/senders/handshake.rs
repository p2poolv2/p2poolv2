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
#[cfg(test)]
#[mockall_double::double]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
#[cfg(not(test))]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
use bitcoin::BlockHash;
use bitcoin::hashes::Hash;
use std::error::Error;
use tokio::sync::mpsc;
use tracing::{debug, error};

/// Send a handshake message to a peer with our confirmed tip height and hash.
///
/// Both sides of a connection send this on establishment so each can
/// determine whether it needs to sync headers from the other.
pub async fn send_handshake<C>(
    peer_id: libp2p::PeerId,
    chain_store_handle: ChainStoreHandle,
    swarm_tx: mpsc::Sender<SwarmSend<C>>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let tip_height = match chain_store_handle.get_tip_height() {
        Ok(Some(height)) => height,
        Ok(None) => 0,
        Err(_) => 0,
    };

    let tip_hash = match chain_store_handle.get_chain_tip() {
        Ok(hash) => hash,
        Err(_) => BlockHash::all_zeros(),
    };

    let handshake_message = Message::Handshake(HandshakeData {
        tip_height,
        tip_hash,
    });

    debug!("Sending Handshake to peer {peer_id}: height={tip_height}, hash={tip_hash}");

    if let Err(send_error) = swarm_tx
        .send(SwarmSend::Request(peer_id, handshake_message))
        .await
    {
        error!("Failed to send handshake to peer {peer_id}: {send_error}");
        return Err(format!("Failed to send handshake to peer {peer_id}: {send_error}").into());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use tokio::sync::mpsc::channel;

    #[tokio::test]
    async fn test_send_handshake_with_existing_chain() {
        let (swarm_tx, mut swarm_rx) = channel::<SwarmSend<Message>>(1);
        let peer_id = libp2p::PeerId::random();
        let mut chain_store_handle = ChainStoreHandle::default();

        let tip_hash =
            BlockHash::from_str("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5")
                .unwrap();

        chain_store_handle
            .expect_get_tip_height()
            .times(1)
            .return_once(|| Ok(Some(42)));

        chain_store_handle
            .expect_get_chain_tip()
            .times(1)
            .return_once(move || Ok(tip_hash));

        let result = send_handshake(peer_id, chain_store_handle, swarm_tx).await;
        assert!(result.is_ok());

        if let Some(SwarmSend::Request(received_peer_id, message)) = swarm_rx.recv().await {
            assert_eq!(received_peer_id, peer_id);
            match message {
                Message::Handshake(data) => {
                    assert_eq!(data.tip_height, 42);
                    assert_eq!(data.tip_hash, tip_hash);
                }
                _ => panic!("Expected Handshake message"),
            }
        } else {
            panic!("No message received");
        }
    }

    #[tokio::test]
    async fn test_send_handshake_fresh_node_with_genesis() {
        let (swarm_tx, mut swarm_rx) = channel::<SwarmSend<Message>>(1);
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

        let result = send_handshake(peer_id, chain_store_handle, swarm_tx).await;
        assert!(result.is_ok());

        if let Some(SwarmSend::Request(received_peer_id, message)) = swarm_rx.recv().await {
            assert_eq!(received_peer_id, peer_id);
            match message {
                Message::Handshake(data) => {
                    assert_eq!(data.tip_height, 0);
                    assert_eq!(data.tip_hash, genesis_hash);
                }
                _ => panic!("Expected Handshake message"),
            }
        } else {
            panic!("No message received");
        }
    }

    #[tokio::test]
    async fn test_send_handshake_channel_closed() {
        let (swarm_tx, _) = channel::<SwarmSend<()>>(1);
        let peer_id = libp2p::PeerId::random();
        let mut chain_store_handle = ChainStoreHandle::default();

        chain_store_handle
            .expect_get_tip_height()
            .times(1)
            .return_once(|| Ok(Some(10)));

        chain_store_handle
            .expect_get_chain_tip()
            .times(1)
            .return_once(|| Ok(BlockHash::all_zeros()));

        let swarm_tx_clone = swarm_tx.clone();
        drop(swarm_tx_clone);

        let result = send_handshake(peer_id, chain_store_handle, swarm_tx).await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Failed to send handshake")
        );
    }
}
