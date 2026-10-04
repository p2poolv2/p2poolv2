// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::node::SwarmSend;
use crate::node::messages::{HandshakeData, Message};
use crate::node::p2p_message_handlers::senders::send_getheaders;
#[cfg(test)]
#[mockall_double::double]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
#[cfg(not(test))]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
use crate::store::block_tx_metadata::Status;
use crate::store::writer::StoreError;
use std::error::Error;
use tokio::sync::mpsc;
use tracing::{debug, error};

/// Handle a Handshake message received from a peer.
///
/// Sends an Ack response on the request-response channel, then sends a
/// getheaders request unless the peer's confirmed tip is a block we have fully
/// validated -- including when our own tip is *higher*. Height alone does not say which
/// chain has more work: a node can be ahead on a lighter fork, and with a
/// height-only rule it would never ask and never learn of the heavier chain.
/// The response goes through header validation and `organise_header`, which
/// compare real chain work.
///
/// A `BlockValid` tip needs no request: validation waits for the bodies of
/// every ancestor down to the prune boundary, so we already hold the peer's
/// whole chain -- whether it is a lower block on our chain (a peer that is
/// behind) or a fork we already know. Asking such a peer would page every
/// header from a sparse locator entry up to its tip, all of them stored.
///
/// A tip held only as a header still gets a request. Header metadata does not
/// imply bodies (a disconnect can drop in-flight block requests), and the
/// peer's empty `ShareHeaders` reply is what triggers `trigger_block_fetch` for
/// the missing bodies. The locator walks exponentially back to genesis, so for
/// an unknown tip it reaches past any fork point and needs no extra depth.
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

    debug!(
        "Received Handshake from peer {peer}: peer_height={}, peer_hash={}, local_height={local_tip_height}, local_hash={local_tip_hash}",
        handshake_data.tip_height, handshake_data.tip_hash
    );

    if local_tip_hash == handshake_data.tip_hash {
        debug!("Tip agrees with peer {peer} at height {local_tip_height}, no sync needed");
        return Ok(());
    }

    let peer_tip_validated = match chain_store_handle.get_block_metadata(&handshake_data.tip_hash) {
        Ok(metadata) => metadata.status == Status::BlockValid,
        Err(StoreError::NotFound(_)) => false,
        Err(error) => {
            error!("Failed to look up peer {peer}'s tip in store: {error}");
            return Err(error.into());
        }
    };

    if peer_tip_validated {
        debug!(
            "Peer {peer}'s tip {}/{} is already validated, no sync needed",
            handshake_data.tip_height, handshake_data.tip_hash
        );
    } else {
        debug!(
            "Peer {peer}'s tip {}/{} is unknown or missing bodies (local {local_tip_height}/{local_tip_hash}), sending getheaders",
            handshake_data.tip_height, handshake_data.tip_hash
        );
        send_getheaders(peer, chain_store_handle, swarm_tx, 0).await?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::SwarmSend;
    use crate::node::messages::Message;
    use crate::store::block_tx_metadata::{BlockMetadata, ChainMembership};
    use crate::store::writer::StoreError;
    use bitcoin::BlockHash;
    use bitcoin::Work;
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
            .expect_get_block_metadata()
            .times(1)
            .return_once(|hash| {
                Err(StoreError::NotFound(format!(
                    "No metadata found for blockhash: {hash}"
                )))
            });

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

    /// A node ahead of a tip it does not hold must still ask: it may be on a
    /// lighter fork, and only the peer's headers can show the heavier chain.
    #[tokio::test]
    async fn test_handle_handshake_local_ahead_of_unknown_tip_sends_getheaders() {
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

        let locator_hash =
            BlockHash::from_str("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5")
                .unwrap();
        chain_store_handle
            .expect_get_block_metadata()
            .times(1)
            .return_once(|hash| {
                Err(StoreError::NotFound(format!(
                    "No metadata found for blockhash: {hash}"
                )))
            });

        chain_store_handle
            .expect_build_locator()
            .times(1)
            .return_once(move |_| Ok(vec![locator_hash]));

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

        match swarm_rx.recv().await.unwrap() {
            SwarmSend::Response(channel, Message::Ack) => assert_eq!(channel, 2u32),
            _ => panic!("Expected SwarmSend::Response with Ack"),
        }

        match swarm_rx.recv().await.unwrap() {
            SwarmSend::Request(sent_peer, Message::GetShareHeaders(locator, _)) => {
                assert_eq!(sent_peer, peer_id);
                assert_eq!(locator, vec![locator_hash]);
            }
            _ => panic!("Expected SwarmSend::Request with GetShareHeaders"),
        }
    }

    /// A peer behind us on our own chain advertises a tip we have validated, so
    /// asking would only page back headers we have stored.
    #[tokio::test]
    async fn test_handle_handshake_local_ahead_of_validated_tip_sends_only_ack() {
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

        chain_store_handle
            .expect_get_block_metadata()
            .withf(move |hash| *hash == peer_tip_hash)
            .times(1)
            .return_once(|_| {
                Ok(BlockMetadata {
                    expected_height: Some(5),
                    chain_work: Work::from_be_bytes([
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 6, 0, 6,
                    ]),
                    status: Status::BlockValid,
                    chain: ChainMembership::Confirmed,
                })
            });

        let (swarm_tx, mut swarm_rx) = mpsc::channel::<SwarmSend<u32>>(10);
        let response_channel = 6u32;

        let handshake_data = HandshakeData {
            tip_height: 5,
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

        match swarm_rx.recv().await.unwrap() {
            SwarmSend::Response(channel, Message::Ack) => assert_eq!(channel, 6u32),
            _ => panic!("Expected SwarmSend::Response with Ack"),
        }

        assert!(
            swarm_rx.try_recv().is_err(),
            "No getheaders should be sent for a tip we already hold"
        );
    }

    /// A tip held only as a header may still be missing bodies; the peer's
    /// empty reply is what triggers the block fetch, so we must still ask.
    #[tokio::test]
    async fn test_handle_handshake_known_tip_without_bodies_sends_getheaders() {
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

        chain_store_handle
            .expect_get_block_metadata()
            .withf(move |hash| *hash == peer_tip_hash)
            .times(1)
            .return_once(|_| {
                Ok(BlockMetadata {
                    expected_height: Some(12),
                    chain_work: Work::from_be_bytes([
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 6, 0, 6,
                    ]),
                    status: Status::HeaderValid,
                    chain: ChainMembership::Candidate,
                })
            });

        chain_store_handle
            .expect_build_locator()
            .times(1)
            .return_once(move |_| Ok(vec![peer_tip_hash]));

        let (swarm_tx, mut swarm_rx) = mpsc::channel::<SwarmSend<u32>>(10);
        let response_channel = 8u32;

        let handshake_data = HandshakeData {
            tip_height: 12,
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

        match swarm_rx.recv().await.unwrap() {
            SwarmSend::Response(channel, Message::Ack) => assert_eq!(channel, 8u32),
            _ => panic!("Expected SwarmSend::Response with Ack"),
        }

        match swarm_rx.recv().await.unwrap() {
            SwarmSend::Request(sent_peer, Message::GetShareHeaders(locator, _)) => {
                assert_eq!(sent_peer, peer_id);
                assert_eq!(locator, vec![peer_tip_hash]);
            }
            _ => panic!("Expected SwarmSend::Request with GetShareHeaders"),
        }
    }

    #[tokio::test]
    async fn test_handle_handshake_peer_tip_lookup_error_propagates() {
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

        chain_store_handle
            .expect_get_block_metadata()
            .times(1)
            .return_once(|_| {
                Err(StoreError::Serialization(
                    "Error deserializing block metadata".to_string(),
                ))
            });

        let (swarm_tx, mut swarm_rx) = mpsc::channel::<SwarmSend<u32>>(10);
        let response_channel = 7u32;

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
        assert!(result.is_err());

        match swarm_rx.recv().await.unwrap() {
            SwarmSend::Response(_, Message::Ack) => {}
            _ => panic!("Expected SwarmSend::Response with Ack"),
        }
        assert!(swarm_rx.try_recv().is_err());
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
            .expect_get_block_metadata()
            .times(1)
            .return_once(|hash| {
                Err(StoreError::NotFound(format!(
                    "No metadata found for blockhash: {hash}"
                )))
            });

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
            .expect_get_block_metadata()
            .times(1)
            .return_once(|hash| {
                Err(StoreError::NotFound(format!(
                    "No metadata found for blockhash: {hash}"
                )))
            });

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
