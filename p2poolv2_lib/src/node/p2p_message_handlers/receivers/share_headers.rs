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

use crate::node::p2p_message_handlers::MAX_HEADERS;
use crate::node::{SwarmSend, messages::Message};
#[cfg(test)]
#[mockall_double::double]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
#[cfg(not(test))]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
use crate::shares::share_block::ShareHeader;
use crate::shares::validation::validate_share_header;
use bitcoin::{BlockHash, hashes::Hash};
use std::error::Error;
use tokio::sync::mpsc;
use tracing::{debug, error, info};

/// Handle ShareHeaders received from a peer.
///
/// The peer_id identifies the peer that sent the headers, allowing
/// follow-up requests to be directed back to the same peer.
///
/// - validate: received share header using shares::validation::validate_share_header
///
/// - getheader: If MAX_HEADERS headers are received, send getheaders to request next batch
///
/// - getdata: If less than MAX_HEADERs received, request first set of
///   blocks. Then response for blocks will ask for next set of
///   blocks.
pub async fn handle_share_headers<C: Send + Sync>(
    peer_id: libp2p::PeerId,
    share_headers: Vec<ShareHeader>,
    chain_store_handle: ChainStoreHandle,
    swarm_tx: mpsc::Sender<SwarmSend<C>>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let all_valid = share_headers
        .iter()
        .all(|header| validate_share_header(header, &chain_store_handle).is_ok());
    if !all_valid {
        // TODO - Request headers from another peer
        info!("Peer sent invalid share headers. We should try a different peer");
    }

    // When less than max headers are received, we have reached the
    // end of the chain. Even if the chain is shorter than MAX_HEADERS
    if share_headers.len() < MAX_HEADERS {
        debug!("Start requesting blocks using getdata");
    } else {
        debug!("Requesting more share header");
        let stop_block_hash = BlockHash::all_zeros();
        let last_block_hash = share_headers.last().unwrap().block_hash();
        let getheaders_request = Message::GetShareHeaders(vec![last_block_hash], stop_block_hash);
        debug!("Sending getheaders {getheaders_request}");
        if let Err(e) = swarm_tx
            .send(SwarmSend::Request(peer_id, getheaders_request))
            .await
        {
            error!("Failed to send getheaders request: {}", e);
            return Err(format!("Failed to send getheaders request: {e}").into());
        }
    }
    debug!("Received share headers: {:?}", share_headers);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::SwarmSend;
    use crate::node::messages::Message;
    #[mockall_double::double]
    use crate::shares::chain::chain_store_handle::ChainStoreHandle;
    use crate::store::block_tx_metadata::{BlockMetadata, Status};
    use crate::test_utils::TestShareBlockBuilder;
    use bitcoin::Work;
    use mockall::predicate::*;
    use tokio::sync::{mpsc, oneshot};

    /// Build a Vec of share headers with the given count by cloning a
    /// single test header. This avoids constructing thousands of unique
    /// blocks when only the collection length matters.
    fn build_share_headers(count: usize) -> Vec<ShareHeader> {
        let template_header = TestShareBlockBuilder::new().build().header;
        vec![template_header; count]
    }

    #[tokio::test]
    async fn test_fewer_than_max_headers_does_not_send_getheaders() {
        let peer_id = libp2p::PeerId::random();
        let chain_store_handle = ChainStoreHandle::default();
        let (swarm_tx, mut swarm_rx) = mpsc::channel::<SwarmSend<oneshot::Sender<Message>>>(32);

        let share_headers = build_share_headers(10);

        let result =
            handle_share_headers(peer_id, share_headers, chain_store_handle, swarm_tx).await;

        assert!(result.is_ok());

        // No follow-up request should have been sent
        assert!(swarm_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_empty_headers_does_not_send_getheaders() {
        let peer_id = libp2p::PeerId::random();
        let chain_store_handle = ChainStoreHandle::default();
        let (swarm_tx, mut swarm_rx) = mpsc::channel::<SwarmSend<oneshot::Sender<Message>>>(32);

        let share_headers: Vec<ShareHeader> = Vec::new();

        let result =
            handle_share_headers(peer_id, share_headers, chain_store_handle, swarm_tx).await;

        assert!(result.is_ok());
        assert!(swarm_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_max_headers_sends_getheaders_to_same_peer() {
        let peer_id = libp2p::PeerId::random();
        let chain_store_handle = ChainStoreHandle::default();
        let (swarm_tx, mut swarm_rx) = mpsc::channel::<SwarmSend<oneshot::Sender<Message>>>(32);

        let share_headers = build_share_headers(MAX_HEADERS);
        let last_block_hash = share_headers.last().unwrap().block_hash();

        let result =
            handle_share_headers(peer_id, share_headers, chain_store_handle, swarm_tx).await;

        assert!(result.is_ok());

        let swarm_message = swarm_rx
            .try_recv()
            .expect("expected a follow-up getheaders request");
        match swarm_message {
            SwarmSend::Request(sent_peer_id, Message::GetShareHeaders(locator, stop_hash)) => {
                assert_eq!(sent_peer_id, peer_id, "request must target the same peer");
                assert_eq!(locator, vec![last_block_hash]);
                assert_eq!(stop_hash, BlockHash::all_zeros());
            }
            other => panic!("expected SwarmSend::Request with GetShareHeaders, got: {other:?}"),
        }
    }
}
