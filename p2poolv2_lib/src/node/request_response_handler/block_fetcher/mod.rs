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
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Maximum number of in-flight block requests per peer.
const MAX_IN_FLIGHT_PER_PEER: usize = 16;

/// Initial in flight tracker capacity
const INITIAL_IN_FLIGHT_CAPACITY: usize = 64;

/// Default timeout for a single block request before retrying.
/// Should remain same as libp2p request timeout.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// How often the fetcher checks for timed-out requests.
const TICK_INTERVAL: Duration = Duration::from_secs(5);

/// Channel capacity for block fetcher events.
const BLOCK_FETCHER_CHANNEL_CAPACITY: usize = 8192;

/// Number of blockhashes moved from the backlog into the pending
/// queue at a time. The next batch is loaded only after the current
/// batch is fully dispatched and all responses have been received,
/// bounding memory in the downstream block receiver.
const FETCH_BATCH_SIZE: usize = 1000;

/// A blockhash queued for fetching, with an optional preferred peer
/// that is known to have the block body (the inv/headers source).
/// When preferred_peer is Some, dispatch targets that peer first.
/// When None, round-robin is used for load distribution.
struct PendingBlock {
    blockhash: BlockHash,
    preferred_peer: Option<PeerId>,
}

/// Events sent to the block fetcher from p2p message handlers.
pub enum BlockFetcherEvent {
    /// Blocks identified by handle_share_headers.
    /// The peer_id is always added to the peer selector.
    /// When use_peer is true, blocks are fetched from this peer
    /// (steady-state: peer announced the block and has the body).
    /// When false, round-robin distributes across peers (initial sync).
    FetchBlocks {
        blockhashes: Vec<BlockHash>,
        peer_id: PeerId,
        use_peer: bool,
    },
    /// A block request completed (received or not found) and can be removed from in-flight.
    BlockRequestCompleted(BlockHash),
    /// Peers list updated -- used for round-robin distribution.
    PeersUpdated(Vec<PeerId>),
    /// A peer disconnected and should be removed from the selector.
    PeerRemoved(PeerId),
}

impl fmt::Display for BlockFetcherEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlockFetcherEvent::FetchBlocks {
                blockhashes,
                peer_id,
                use_peer,
            } => write!(
                formatter,
                "FetchBlocks({} hashes, peer={}, use_peer={})",
                blockhashes.len(),
                peer_id,
                use_peer
            ),
            BlockFetcherEvent::BlockRequestCompleted(hash) => {
                write!(formatter, "BlockRequestCompleted({hash})")
            }
            BlockFetcherEvent::PeersUpdated(peers) => {
                write!(formatter, "PeersUpdated({} peers)", peers.len())
            }
            BlockFetcherEvent::PeerRemoved(peer_id) => {
                write!(formatter, "PeerRemoved({peer_id})")
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
    /// Blocks waiting to be requested (not yet in-flight).
    /// Holds at most one batch of FETCH_BATCH_SIZE entries.
    pending: VecDeque<PendingBlock>,
    /// Blocks that have not yet been moved into `pending`.
    /// Batches of FETCH_BATCH_SIZE are promoted when the current
    /// batch is fully processed (pending and in_flight both empty).
    backlog: VecDeque<PendingBlock>,
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
            pending: VecDeque::new(),
            backlog: VecDeque::new(),
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
                        Some(BlockFetcherEvent::FetchBlocks { blockhashes, peer_id, use_peer }) => {
                            self.handle_fetch_blocks(blockhashes, peer_id, use_peer).await;
                        }
                        Some(BlockFetcherEvent::BlockRequestCompleted(blockhash)) => {
                            self.handle_block_request_completed(blockhash);
                            self.dispatch_pending_requests().await;
                            self.refill_pending_from_backlog().await;
                        }
                        Some(BlockFetcherEvent::PeersUpdated(peers)) => {
                            debug!("Peers list updated in block fetcher");
                            self.peer_selector.update_peers(peers);
                        }
                        Some(BlockFetcherEvent::PeerRemoved(peer_id)) => {
                            self.handle_peer_removed(peer_id);
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
                    self.refill_pending_from_backlog().await;
                }
            }
        }
    }

    /// Check whether a blockhash is already tracked in any queue.
    fn is_known(&self, blockhash: &BlockHash) -> bool {
        self.in_flight.contains_key(blockhash)
            || self
                .pending
                .iter()
                .any(|entry| entry.blockhash == *blockhash)
            || self
                .backlog
                .iter()
                .any(|entry| entry.blockhash == *blockhash)
    }

    /// Handle a FetchBlocks event by adding new blockhashes to the
    /// backlog and refilling pending if the current batch is done.
    async fn handle_fetch_blocks(
        &mut self,
        blockhashes: Vec<BlockHash>,
        peer_id: PeerId,
        use_peer: bool,
    ) {
        info!(
            "Block fetcher received {} blockhashes to fetch from peer {}, use_peer: {}",
            blockhashes.len(),
            peer_id,
            use_peer
        );

        self.peer_selector.add_peer(peer_id);

        let preferred_peer = if use_peer { Some(peer_id) } else { None };

        for blockhash in blockhashes {
            if !self.is_known(&blockhash) {
                self.backlog.push_back(PendingBlock {
                    blockhash,
                    preferred_peer,
                });
            }
        }

        self.refill_pending_from_backlog().await;
    }

    /// Remove a blockhash from in-flight tracking when a block request completes.
    /// Also removes from pending and backlog so the block is not re-requested.
    fn handle_block_request_completed(&mut self, blockhash: BlockHash) {
        if let Some(request) = self.in_flight.remove(&blockhash) {
            debug!("Block request completed, removed from in-flight: {blockhash}");
            self.peer_selector.record_completion(request.peer_id);
        }
        self.pending.retain(|entry| entry.blockhash != blockhash);
        self.backlog.retain(|entry| entry.blockhash != blockhash);
    }

    /// Remove a disconnected peer from the selector and drop any
    /// in-flight requests that were assigned to it.
    ///
    /// In-flight requests are intentionally not re-queued to other
    /// peers. A peer may have sent cheap headers and then disconnected,
    /// and propagating those requests to other peers who do not have
    /// the blocks would waste their bandwidth.
    fn handle_peer_removed(&mut self, peer_id: PeerId) {
        info!("Removing peer {peer_id} from block fetcher");
        self.peer_selector.remove_peer(&peer_id);

        let dropped: Vec<BlockHash> = self
            .in_flight
            .iter()
            .filter(|(_, request)| request.peer_id == peer_id)
            .map(|(blockhash, _)| *blockhash)
            .collect();

        for blockhash in &dropped {
            self.in_flight.remove(blockhash);
        }

        if !dropped.is_empty() {
            info!(
                "Dropped {} in-flight requests from removed peer {peer_id}",
                dropped.len()
            );
        }

        for entry in &mut self.pending {
            if entry.preferred_peer == Some(peer_id) {
                entry.preferred_peer = None;
            }
        }
        for entry in &mut self.backlog {
            if entry.preferred_peer == Some(peer_id) {
                entry.preferred_peer = None;
            }
        }
    }

    /// Move the next batch of blockhashes from the backlog into
    /// pending when the current batch is fully processed.
    async fn refill_pending_from_backlog(&mut self) {
        if !self.pending.is_empty() || !self.in_flight.is_empty() {
            return;
        }
        if self.backlog.is_empty() {
            return;
        }

        let batch_size = FETCH_BATCH_SIZE.min(self.backlog.len());
        self.pending.extend(self.backlog.drain(..batch_size));

        info!(
            "Loaded batch of {} blocks from backlog ({} remaining)",
            self.pending.len(),
            self.backlog.len()
        );

        self.dispatch_pending_requests().await;
    }

    /// Send GetData::Block requests for pending blockhashes,
    /// respecting per-peer in-flight limits.  Send GetData::Block
    /// requests for pending blocks, respecting per-peer in-flight
    /// limits. When a pending block has a preferred peer
    /// (steady-state inv handling), dispatch to that peer.  Otherwise
    /// use round-robin (initial sync / retry).
    async fn dispatch_pending_requests(&mut self) {
        if !self.peer_selector.has_peers() || self.pending.is_empty() {
            return;
        }

        let mut dispatch_count = 0usize;

        while let Some(pending_block) = self.pending.front() {
            let blockhash = pending_block.blockhash;
            let peer_id = match self.select_peer_for_block(pending_block.preferred_peer) {
                Some(peer_id) => peer_id,
                None => return,
            };

            let message = Message::GetData(GetData::Block(blockhash));
            debug!("Sending GetData for {blockhash}");
            if let Err(send_error) = self
                .swarm_tx
                .send(SwarmSend::Request(peer_id, message))
                .await
            {
                error!("Failed to send GetData::Block request: {send_error}");
                return;
            }

            self.pending.pop_front();
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

        let timed_out = self.collect_timed_out_requests();

        for blockhash in timed_out {
            let old_request = self.in_flight.remove(&blockhash).unwrap();
            warn!(
                "Block request timed out for {blockhash}, was sent to peer {}",
                old_request.peer_id
            );
            self.peer_selector.record_completion(old_request.peer_id);
            self.requeue_for_retry(blockhash);
        }
    }

    /// Select a peer for a block request. Uses the preferred peer if
    /// available and has capacity, otherwise falls back to round-robin.
    /// Returns None if all peers are at capacity.
    fn select_peer_for_block(&mut self, preferred_peer: Option<PeerId>) -> Option<PeerId> {
        match preferred_peer {
            Some(preferred) if self.peer_selector.peer_has_capacity(&preferred) => Some(preferred),
            _ => self.peer_selector.select_peer(),
        }
    }

    /// Return blockhashes of in-flight requests that have exceeded
    /// the request timeout.
    fn collect_timed_out_requests(&self) -> Vec<BlockHash> {
        let now = Instant::now();
        self.in_flight
            .iter()
            .filter(|(_, request)| now.duration_since(request.requested_at) > REQUEST_TIMEOUT)
            .map(|(blockhash, _)| *blockhash)
            .collect()
    }

    /// Re-add a block to the front of the pending queue for retry
    /// with round-robin peer selection (no preferred peer).
    fn requeue_for_retry(&mut self, blockhash: BlockHash) {
        let already_pending = self
            .pending
            .iter()
            .any(|entry| entry.blockhash == blockhash);
        if !already_pending {
            self.pending.push_front(PendingBlock {
                blockhash,
                preferred_peer: None,
            });
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
                use_peer: true,
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
                use_peer: true,
            })
            .await
            .unwrap();

        block_fetcher_tx
            .send(BlockFetcherEvent::BlockRequestCompleted(blockhash))
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

        // No preferred peer -- round-robin should distribute across peers
        block_fetcher_tx
            .send(BlockFetcherEvent::FetchBlocks {
                blockhashes: vec![blockhash_one, blockhash_two],
                peer_id: peer_a,
                use_peer: false,
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
    async fn test_block_fetcher_uses_preferred_peer_when_use_peer_true() {
        let (block_fetcher_tx, block_fetcher_rx) = create_block_fetcher_channel();
        let (swarm_tx, mut swarm_rx) = mpsc::channel(64);
        let fetcher = BlockFetcher::new(block_fetcher_rx, swarm_tx);

        let peer_a = PeerId::random();
        let peer_b = PeerId::random();

        // Register both peers so round-robin has two options
        block_fetcher_tx
            .send(BlockFetcherEvent::PeersUpdated(vec![peer_a, peer_b]))
            .await
            .unwrap();

        let blockhash_one = random_blockhash();
        let blockhash_two = random_blockhash();

        // use_peer=true: both blocks should go to peer_a
        block_fetcher_tx
            .send(BlockFetcherEvent::FetchBlocks {
                blockhashes: vec![blockhash_one, blockhash_two],
                peer_id: peer_a,
                use_peer: true,
            })
            .await
            .unwrap();
        drop(block_fetcher_tx);

        let fetcher_handle = tokio::spawn(fetcher.run());

        let message_one = swarm_rx.recv().await.unwrap();
        let message_two = swarm_rx.recv().await.unwrap();

        for message in [message_one, message_two] {
            match message {
                SwarmSend::Request(peer, Message::GetData(GetData::Block(_))) => {
                    assert_eq!(peer, peer_a, "Expected preferred peer_a, got {peer}");
                }
                other => panic!("Expected GetData::Block request, got: {other:?}"),
            }
        }

        let result = fetcher_handle.await.unwrap();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_block_fetcher_falls_back_to_round_robin_when_preferred_at_capacity() {
        let (block_fetcher_tx, block_fetcher_rx) = create_block_fetcher_channel();
        let (swarm_tx, mut swarm_rx) = mpsc::channel(64);
        let fetcher = BlockFetcher::new(block_fetcher_rx, swarm_tx);

        let peer_a = PeerId::random();
        let peer_b = PeerId::random();

        block_fetcher_tx
            .send(BlockFetcherEvent::PeersUpdated(vec![peer_a, peer_b]))
            .await
            .unwrap();

        // Fill peer_a to capacity + 1 overflow block, all preferring peer_a
        let all_hashes: Vec<BlockHash> = (0..MAX_IN_FLIGHT_PER_PEER + 1)
            .map(|_| random_blockhash())
            .collect();
        let overflow_hash = all_hashes[MAX_IN_FLIGHT_PER_PEER];

        block_fetcher_tx
            .send(BlockFetcherEvent::FetchBlocks {
                blockhashes: all_hashes.clone(),
                peer_id: peer_a,
                use_peer: true,
            })
            .await
            .unwrap();
        drop(block_fetcher_tx);

        let fetcher_handle = tokio::spawn(fetcher.run());

        // First MAX_IN_FLIGHT_PER_PEER requests go to peer_a
        for _ in 0..MAX_IN_FLIGHT_PER_PEER {
            let message = swarm_rx.recv().await.unwrap();
            match message {
                SwarmSend::Request(peer, Message::GetData(GetData::Block(_))) => {
                    assert_eq!(
                        peer, peer_a,
                        "Capacity requests should go to preferred peer_a"
                    );
                }
                other => panic!("Expected GetData::Block request, got: {other:?}"),
            }
        }

        // The overflow request should fall back to peer_b
        let message = swarm_rx.recv().await.unwrap();
        match message {
            SwarmSend::Request(peer, Message::GetData(GetData::Block(hash))) => {
                assert_eq!(hash, overflow_hash);
                assert_eq!(
                    peer, peer_b,
                    "Expected fallback to peer_b when peer_a is at capacity"
                );
            }
            other => panic!("Expected GetData::Block request, got: {other:?}"),
        }

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
                use_peer: true,
            })
            .await
            .unwrap();

        block_fetcher_tx
            .send(BlockFetcherEvent::FetchBlocks {
                blockhashes: vec![blockhash],
                peer_id,
                use_peer: true,
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
                use_peer: true,
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

    #[tokio::test]
    async fn test_block_fetcher_batches_from_backlog() {
        let (block_fetcher_tx, block_fetcher_rx) = create_block_fetcher_channel();
        let (swarm_tx, mut swarm_rx) = mpsc::channel(2048);
        let fetcher = BlockFetcher::new(block_fetcher_rx, swarm_tx);

        let peer_id = PeerId::random();
        let total_blocks = FETCH_BATCH_SIZE + 500;
        let blockhashes: Vec<BlockHash> = (0..total_blocks).map(|_| random_blockhash()).collect();

        block_fetcher_tx
            .send(BlockFetcherEvent::FetchBlocks {
                blockhashes: blockhashes.clone(),
                peer_id,
                use_peer: true,
            })
            .await
            .unwrap();

        let fetcher_handle = tokio::spawn(fetcher.run());

        // Yield to let the fetcher process the FetchBlocks event
        tokio::task::yield_now().await;

        // With 1 peer and MAX_IN_FLIGHT_PER_PEER=16, only 16 blocks
        // are dispatched at a time. Drain and complete them all,
        // counting the total dispatched across all batches.
        let mut total_dispatched = 0usize;
        loop {
            match swarm_rx.try_recv() {
                Ok(SwarmSend::Request(_, Message::GetData(GetData::Block(hash)))) => {
                    total_dispatched += 1;
                    block_fetcher_tx
                        .send(BlockFetcherEvent::BlockRequestCompleted(hash))
                        .await
                        .unwrap();
                    // Yield so the fetcher processes the completion
                    tokio::task::yield_now().await;
                }
                _ => {
                    // Yield and try once more in case the fetcher
                    // needs a cycle to refill from backlog
                    tokio::task::yield_now().await;
                    match swarm_rx.try_recv() {
                        Ok(SwarmSend::Request(_, Message::GetData(GetData::Block(hash)))) => {
                            total_dispatched += 1;
                            block_fetcher_tx
                                .send(BlockFetcherEvent::BlockRequestCompleted(hash))
                                .await
                                .unwrap();
                            tokio::task::yield_now().await;
                        }
                        _ => {
                            // Truly done
                            break;
                        }
                    }
                }
            }
        }

        assert_eq!(
            total_dispatched, total_blocks,
            "All blocks should be dispatched across batches"
        );

        drop(block_fetcher_tx);
        let result = fetcher_handle.await.unwrap();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_block_fetcher_peer_removed_drops_in_flight() {
        let (block_fetcher_tx, block_fetcher_rx) = create_block_fetcher_channel();
        let (swarm_tx, mut swarm_rx) = mpsc::channel(64);
        let fetcher = BlockFetcher::new(block_fetcher_rx, swarm_tx);

        let peer_a = PeerId::random();
        let peer_b = PeerId::random();

        // Register both peers
        block_fetcher_tx
            .send(BlockFetcherEvent::PeersUpdated(vec![peer_a, peer_b]))
            .await
            .unwrap();

        let blockhash = random_blockhash();

        block_fetcher_tx
            .send(BlockFetcherEvent::FetchBlocks {
                blockhashes: vec![blockhash],
                peer_id: peer_a,
                use_peer: true,
            })
            .await
            .unwrap();

        let fetcher_handle = tokio::spawn(fetcher.run());

        // Drain the initial request
        let initial_request = swarm_rx.recv().await.unwrap();
        let initial_peer = match initial_request {
            SwarmSend::Request(peer, Message::GetData(GetData::Block(hash))) => {
                assert_eq!(hash, blockhash);
                peer
            }
            other => panic!("Expected GetData::Block, got: {other:?}"),
        };

        // Remove the peer that got the request -- in-flight should be
        // dropped, not re-queued to other peers
        block_fetcher_tx
            .send(BlockFetcherEvent::PeerRemoved(initial_peer))
            .await
            .unwrap();

        // Give the fetcher time to process the event
        tokio::task::yield_now().await;

        drop(block_fetcher_tx);

        // No retry request should be sent
        assert!(
            swarm_rx.try_recv().is_err(),
            "in-flight requests from removed peer should be dropped, not retried"
        );

        let result = fetcher_handle.await.unwrap();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_block_fetcher_peer_removed_no_in_flight_is_noop() {
        let (block_fetcher_tx, block_fetcher_rx) = create_block_fetcher_channel();
        let (swarm_tx, mut swarm_rx) = mpsc::channel(32);
        let fetcher = BlockFetcher::new(block_fetcher_rx, swarm_tx);

        let peer_a = PeerId::random();
        let peer_b = PeerId::random();

        block_fetcher_tx
            .send(BlockFetcherEvent::PeersUpdated(vec![peer_a, peer_b]))
            .await
            .unwrap();

        // Remove a peer with nothing in-flight
        block_fetcher_tx
            .send(BlockFetcherEvent::PeerRemoved(peer_a))
            .await
            .unwrap();

        drop(block_fetcher_tx);

        let fetcher_handle = tokio::spawn(fetcher.run());

        // No requests should be sent
        assert!(
            swarm_rx.try_recv().is_err(),
            "no requests should be sent when removed peer has no in-flight"
        );

        let result = fetcher_handle.await.unwrap();
        assert!(result.is_ok());
    }
}
