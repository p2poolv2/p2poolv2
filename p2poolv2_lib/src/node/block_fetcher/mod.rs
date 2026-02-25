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

//! Concurrent block fetcher for downloading blocks from peers.
//!
//! After header sync builds the candidate chain, the BlockFetcher
//! distributes `GetData::Block` requests across connected peers and
//! tracks in-flight requests with timeouts. When a block is received,
//! the corresponding in-flight entry is removed.

mod peer_selector;

use crate::node::SwarmSend;
use crate::node::messages::{GetData, Message};
use bitcoin::BlockHash;
use libp2p::PeerId;
use libp2p::request_response::ResponseChannel;
use peer_selector::PeerSelector;
use std::collections::HashMap;
use std::fmt;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Maximum number of in-flight block requests per peer.
const MAX_IN_FLIGHT_PER_PEER: usize = 16;

/// Initial in flight tracker capacity
const INITIAL_IN_FLIGHT_CAPACITY: usize = 64;

/// Default timeout for a single block request before retrying.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// How often the fetcher checks for timed-out requests.
const TICK_INTERVAL: Duration = Duration::from_secs(5);

/// Channel capacity for block fetcher events.
const BLOCK_FETCHER_CHANNEL_CAPACITY: usize = 256;

/// Events sent to the block fetcher from p2p message handlers.
pub enum BlockFetcherEvent {
    /// Blocks identified by handle_share_headers
    FetchBlocks {
        blockhashes: Vec<BlockHash>,
        /// If peer is not known it is added to the list of peers
        /// block fetcher knows about.
        peer_id: PeerId,
    },
    /// A block was received from a peer, and can now be remove from in-flight.
    BlockReceived(BlockHash),
    /// Peers list updated -- used for round-robin distribution.
    PeersUpdated(Vec<PeerId>),
}

impl fmt::Display for BlockFetcherEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlockFetcherEvent::FetchBlocks {
                blockhashes,
                peer_id,
            } => write!(
                formatter,
                "FetchBlocks({} hashes, peer={})",
                blockhashes.len(),
                peer_id
            ),
            BlockFetcherEvent::BlockReceived(hash) => {
                write!(formatter, "BlockReceived({hash})")
            }
            BlockFetcherEvent::PeersUpdated(peers) => {
                write!(formatter, "PeersUpdated({} peers)", peers.len())
            }
        }
    }
}

/// Sender half of the block fetcher channel.
pub type BlockFetcherHandle = mpsc::Sender<BlockFetcherEvent>;

/// Receiver half of the block fetcher channel.
pub type BlockFetcherReceiver = mpsc::Receiver<BlockFetcherEvent>;

/// Create a block fetcher channel with bounded capacity.
pub fn create_block_fetcher_channel() -> (BlockFetcherHandle, BlockFetcherReceiver) {
    mpsc::channel(BLOCK_FETCHER_CHANNEL_CAPACITY)
}

/// Tracks a single in-flight block request.
struct InFlightRequest {
    peer_id: PeerId,
    requested_at: Instant,
}

/// Error raised by block fetcher.
#[derive(Debug)]
pub struct BlockFetcherError {
    message: String,
}

impl fmt::Display for BlockFetcherError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "BlockFetcherError: {}", self.message)
    }
}

impl std::error::Error for BlockFetcherError {}

/// Concurrent block fetcher that distributes requests across peers.
///
/// Receives `BlockFetcherEvent` values and sends `GetData::Block`
/// requests to peers via `swarm_tx`. Tracks in-flight requests and
/// retries timed-out requests from different peers.
pub struct BlockFetcher {
    event_rx: BlockFetcherReceiver,
    swarm_tx: mpsc::Sender<SwarmSend<ResponseChannel<Message>>>,
    /// Blockhashes that have been requested -- inflight
    in_flight: HashMap<BlockHash, InFlightRequest>,
    /// Blockhashes waiting to be requested (not yet in-flight).
    pending: Vec<BlockHash>,
    /// Peer selection with round-robin distribution and capacity tracking.
    peer_selector: PeerSelector,
}

impl BlockFetcher {
    /// Creates a new block fetcher.
    pub fn new(
        event_rx: BlockFetcherReceiver,
        swarm_tx: mpsc::Sender<SwarmSend<ResponseChannel<Message>>>,
    ) -> Self {
        Self {
            event_rx,
            swarm_tx,
            in_flight: HashMap::with_capacity(INITIAL_IN_FLIGHT_CAPACITY),
            pending: Vec::new(),
            peer_selector: PeerSelector::new(),
        }
    }

    /// Runs the block fetcher until the channel closes or a fatal error is encountered.
    pub async fn run(mut self) -> Result<(), BlockFetcherError> {
        info!("Block fetcher started");
        let mut tick_interval = tokio::time::interval(TICK_INTERVAL);

        loop {
            tokio::select! {
                event = self.event_rx.recv() => {
                    match event {
                        Some(BlockFetcherEvent::FetchBlocks { blockhashes, peer_id }) => {
                            self.handle_fetch_blocks(blockhashes, peer_id).await;
                        }
                        Some(BlockFetcherEvent::BlockReceived(blockhash)) => {
                            self.handle_block_received(blockhash);
                            self.dispatch_pending_requests().await;
                        }
                        Some(BlockFetcherEvent::PeersUpdated(peers)) => {
                            debug!("Peers list updated in block fetcher");
                            self.peer_selector.update_peers(peers);
                        }
                        None => {
                            info!("Block fetcher stopped -- channel closed");
                            return Ok(());
                        }
                    }
                }
                _ = tick_interval.tick() => {
                    self.retry_timed_out_requests().await;
                    self.dispatch_pending_requests().await;
                }
            }
        }
    }

    /// Handle a FetchBlocks event by adding blockhashes to the pending queue
    /// and immediately dispatching requests to peers to trigget getblock.
    async fn handle_fetch_blocks(&mut self, blockhashes: Vec<BlockHash>, peer_id: PeerId) {
        info!(
            "Block fetcher received {} blockhashes to fetch from peer {}",
            blockhashes.len(),
            peer_id
        );

        self.peer_selector.add_peer(peer_id);

        // Add blockhashes that are not already in-flight or pending
        for blockhash in blockhashes {
            if !self.in_flight.contains_key(&blockhash) && !self.pending.contains(&blockhash) {
                self.pending.push(blockhash);
            }
        }

        self.dispatch_pending_requests().await;
    }

    /// Remove a blockhash from in-flight tracking when the block is received.
    /// The caller should dispatch pending requests afterwards since capacity
    /// may have been freed.
    fn handle_block_received(&mut self, blockhash: BlockHash) {
        if let Some(request) = self.in_flight.remove(&blockhash) {
            debug!("Block received, removed from in-flight: {blockhash}");
            self.peer_selector.record_completion(request.peer_id);
        }
        // Also remove from pending in case it was queued but not yet sent
        self.pending.retain(|hash| *hash != blockhash);
    }

    /// Send GetData::Block requests for pending blockhashes, respecting
    /// per-peer in-flight limits.
    async fn dispatch_pending_requests(&mut self) {
        if !self.peer_selector.has_peers() || self.pending.is_empty() {
            return;
        }

        let mut dispatch_count = 0usize;

        while let Some(&blockhash) = self.pending.first() {
            let peer_id = match self.peer_selector.select_peer() {
                Some(peer_id) => peer_id,
                None => {
                    // All peers are at capacity -- keep remaining in pending
                    return;
                }
            };

            let message = Message::GetData(GetData::Block(blockhash));
            if let Err(send_error) = self
                .swarm_tx
                .send(SwarmSend::Request(peer_id, message))
                .await
            {
                error!("Failed to send GetData::Block request: {send_error}");
                return;
            }

            self.pending.remove(0);
            self.in_flight.insert(
                blockhash,
                InFlightRequest {
                    peer_id,
                    requested_at: Instant::now(),
                },
            );
            self.peer_selector.record_dispatch(peer_id);
            dispatch_count += 1;
        }

        if dispatch_count > 0 {
            debug!(
                "Dispatched {} block requests, {} remaining pending",
                dispatch_count,
                self.pending.len()
            );
        }
    }

    /// Check for timed-out in-flight requests and enqueue to pending
    /// so that this is retried using a different peer. Dispatch is
    /// called immediately after calling this in the event loop.
    async fn retry_timed_out_requests(&mut self) {
        if self.in_flight.is_empty() {
            return;
        }

        let now = Instant::now();
        let mut timed_out = Vec::new();

        for (blockhash, request) in &self.in_flight {
            if now.duration_since(request.requested_at) > REQUEST_TIMEOUT {
                timed_out.push(*blockhash);
            }
        }

        for blockhash in timed_out {
            let old_request = self.in_flight.remove(&blockhash).unwrap();
            warn!(
                "Block request timed out for {blockhash}, was sent to peer {}",
                old_request.peer_id
            );
            self.peer_selector.record_completion(old_request.peer_id);
            // Re-add to pending for retry from a different peer
            if !self.pending.contains(&blockhash) {
                self.pending.push(blockhash);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use tokio::sync::mpsc;

    fn random_blockhash() -> BlockHash {
        BlockHash::from_byte_array(rand::random())
    }

    #[tokio::test]
    async fn test_block_fetcher_stops_on_channel_close() {
        let (block_fetcher_tx, block_fetcher_rx) = create_block_fetcher_channel();
        let (swarm_tx, _swarm_rx) = mpsc::channel(32);
        let fetcher = BlockFetcher::new(block_fetcher_rx, swarm_tx);

        drop(block_fetcher_tx);

        let result = fetcher.run().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_block_fetcher_dispatches_to_peer() {
        let (block_fetcher_tx, block_fetcher_rx) = create_block_fetcher_channel();
        let (swarm_tx, mut swarm_rx) = mpsc::channel(32);
        let fetcher = BlockFetcher::new(block_fetcher_rx, swarm_tx);

        let peer_id = PeerId::random();
        let blockhash = random_blockhash();

        block_fetcher_tx
            .send(BlockFetcherEvent::FetchBlocks {
                blockhashes: vec![blockhash],
                peer_id,
            })
            .await
            .unwrap();
        drop(block_fetcher_tx);

        let fetcher_handle = tokio::spawn(fetcher.run());

        // Check that a GetData::Block request was sent
        let message = swarm_rx.recv().await.unwrap();
        match message {
            SwarmSend::Request(
                sent_peer,
                Message::GetData(GetData::Block(requested_blockhash)),
            ) => {
                assert_eq!(sent_peer, peer_id);
                assert_eq!(requested_blockhash, blockhash);
            }
            other => panic!("Expected SwarmSend::Request with GetData::Block, got: {other:?}"),
        }

        let result = fetcher_handle.await.unwrap();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_block_fetcher_removes_received_block() {
        let (block_fetcher_tx, block_fetcher_rx) = create_block_fetcher_channel();
        let (swarm_tx, mut swarm_rx) = mpsc::channel(32);
        let fetcher = BlockFetcher::new(block_fetcher_rx, swarm_tx);

        let peer_id = PeerId::random();
        let blockhash = random_blockhash();

        // Send fetch request, then immediately mark as received
        block_fetcher_tx
            .send(BlockFetcherEvent::FetchBlocks {
                blockhashes: vec![blockhash],
                peer_id,
            })
            .await
            .unwrap();

        block_fetcher_tx
            .send(BlockFetcherEvent::BlockReceived(blockhash))
            .await
            .unwrap();
        drop(block_fetcher_tx);

        let fetcher_handle = tokio::spawn(fetcher.run());

        // Drain the GetData request
        let _request = swarm_rx.recv().await.unwrap();

        let result = fetcher_handle.await.unwrap();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_block_fetcher_round_robin_across_peers() {
        let (block_fetcher_tx, block_fetcher_rx) = create_block_fetcher_channel();
        let (swarm_tx, mut swarm_rx) = mpsc::channel(64);
        let fetcher = BlockFetcher::new(block_fetcher_rx, swarm_tx);

        let peer_a = PeerId::random();
        let peer_b = PeerId::random();

        // Update peers list first
        block_fetcher_tx
            .send(BlockFetcherEvent::PeersUpdated(vec![peer_a, peer_b]))
            .await
            .unwrap();

        let blockhash_one = random_blockhash();
        let blockhash_two = random_blockhash();

        block_fetcher_tx
            .send(BlockFetcherEvent::FetchBlocks {
                blockhashes: vec![blockhash_one, blockhash_two],
                peer_id: peer_a,
            })
            .await
            .unwrap();
        drop(block_fetcher_tx);

        let fetcher_handle = tokio::spawn(fetcher.run());

        // Collect the two requests
        let message_one = swarm_rx.recv().await.unwrap();
        let message_two = swarm_rx.recv().await.unwrap();

        // Requests should use the two different peers
        let mut peers_used = Vec::with_capacity(2);
        for message in [message_one, message_two] {
            match message {
                SwarmSend::Request(peer, Message::GetData(GetData::Block(_))) => {
                    peers_used.push(peer);
                }
                other => panic!("Expected GetData::Block request, got: {other:?}"),
            }
        }

        // Both peers should have been used (round-robin)
        assert!(
            peers_used.contains(&peer_a) && peers_used.contains(&peer_b),
            "Expected requests to both peers, got: {peers_used:?}"
        );

        let result = fetcher_handle.await.unwrap();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_block_fetcher_skips_duplicate_blockhashes() {
        let (block_fetcher_tx, block_fetcher_rx) = create_block_fetcher_channel();
        let (swarm_tx, mut swarm_rx) = mpsc::channel(32);
        let fetcher = BlockFetcher::new(block_fetcher_rx, swarm_tx);

        let peer_id = PeerId::random();
        let blockhash = random_blockhash();

        // Send the same blockhash twice
        block_fetcher_tx
            .send(BlockFetcherEvent::FetchBlocks {
                blockhashes: vec![blockhash],
                peer_id,
            })
            .await
            .unwrap();

        block_fetcher_tx
            .send(BlockFetcherEvent::FetchBlocks {
                blockhashes: vec![blockhash],
                peer_id,
            })
            .await
            .unwrap();
        drop(block_fetcher_tx);

        let fetcher_handle = tokio::spawn(fetcher.run());

        // Should only get one GetData request
        let _request = swarm_rx.recv().await.unwrap();

        // No more requests should follow
        let result = fetcher_handle.await.unwrap();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_block_fetcher_fetch_blocks_adds_unknown_peer() {
        let (block_fetcher_tx, block_fetcher_rx) = create_block_fetcher_channel();
        let (swarm_tx, mut swarm_rx) = mpsc::channel(32);
        let fetcher = BlockFetcher::new(block_fetcher_rx, swarm_tx);

        let peer_id = PeerId::random();
        let blockhash = random_blockhash();

        // No PeersUpdated sent -- the peer comes only from FetchBlocks
        block_fetcher_tx
            .send(BlockFetcherEvent::FetchBlocks {
                blockhashes: vec![blockhash],
                peer_id,
            })
            .await
            .unwrap();
        drop(block_fetcher_tx);

        let fetcher_handle = tokio::spawn(fetcher.run());

        // The block should be dispatched because FetchBlocks adds the peer
        let request = swarm_rx.recv().await.unwrap();
        match request {
            SwarmSend::Request(sent_peer, Message::GetData(GetData::Block(hash))) => {
                assert_eq!(sent_peer, peer_id);
                assert_eq!(hash, blockhash);
            }
            other => panic!("Expected GetData::Block, got: {other:?}"),
        }

        let result = fetcher_handle.await.unwrap();
        assert!(result.is_ok());
    }
}
