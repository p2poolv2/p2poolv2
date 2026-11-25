// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Transport-only fetch layer for share-chain transactions.
//!
//! `TxFetcher` keeps a single in-flight request per txid: it turns
//! `TxFetchHandle::request` calls into wire `GetData::Txid` requests on
//! `swarm_tx` (like `BlockFetcher`, which it mirrors) and correlates one
//! solicited `Transaction` or `NotFound` reply back to the joined callers.
//! The caller owns peer selection and what to do with the result.

use crate::node::SwarmSend;
use crate::node::messages::{GetData, Message};
use bitcoin::Transaction;
use bitcoin::Txid;
use libp2p::PeerId;
use libp2p::request_response::ResponseChannel;
use std::collections::HashMap;
use std::fmt;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;
use tracing::{debug, error, info};

/// Channel capacity for transaction fetcher events.
const TX_FETCHER_CHANNEL_CAPACITY: usize = 1024;

/// Initial pending-flight map capacity.
const INITIAL_IN_FLIGHT_CAPACITY: usize = 64;

/// Per-attempt deadline. Matches the libp2p request-response timeout, so an
/// attempt retires exactly when its wire request dies at the transport
/// instead of waiting on a peer that will not answer.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// How often the fetcher sweeps flights for expired attempts.
const TICK_INTERVAL: Duration = Duration::from_secs(1);

/// Why a transaction fetch did not resolve with a transaction.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TxFetchError {
    /// The asked peer explicitly answered that the transaction is absent.
    #[error("transaction not found")]
    NotFound,
    /// The request could not be completed. This is not an absence verdict.
    #[error("transaction fetch unavailable: {0}")]
    Unavailable(String),
}

/// Events consumed by [`TxFetcher`].
#[derive(Debug)]
pub enum TxFetchEvent {
    /// A caller asks for a transaction, receiving the result on `responder`.
    /// `peer` is the peer to ask; `None` resolves immediately with
    /// [`TxFetchError::Unavailable`]. A request for a txid already in flight
    /// joins that flight without repeating the wire request.
    FetchTransaction {
        txid: Txid,
        peer: Option<PeerId>,
        responder: oneshot::Sender<Result<Transaction, TxFetchError>>,
    },
    /// A transaction arrived from `peer`. It resolves the flight for its
    /// txid when that peer was asked for it; anything else is dropped for
    /// now.
    TransactionReceived {
        peer: PeerId,
        transaction: Transaction,
    },
    /// A peer answered our transaction request with `NotFound`.
    TransactionNotFound { peer: PeerId, txid: Txid },
    /// A peer disconnected; its in-flight request resolves as unavailable.
    PeerRemoved(PeerId),
}

impl fmt::Display for TxFetchEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TxFetchEvent::FetchTransaction { txid, peer, .. } => {
                write!(formatter, "FetchTransaction(txid={txid}, peer={peer:?})")
            }
            TxFetchEvent::TransactionReceived { peer, transaction } => write!(
                formatter,
                "TransactionReceived(txid={}, peer={peer})",
                transaction.compute_txid()
            ),
            TxFetchEvent::TransactionNotFound { peer, txid } => {
                write!(formatter, "TransactionNotFound(txid={txid}, peer={peer})")
            }
            TxFetchEvent::PeerRemoved(peer) => write!(formatter, "PeerRemoved({peer})"),
        }
    }
}

/// Handle for driving [`TxFetcher`].
#[derive(Clone)]
pub struct TxFetchHandle {
    event_tx: mpsc::Sender<TxFetchEvent>,
}

impl TxFetchHandle {
    /// Send an event to the fetcher.
    pub async fn send(&self, event: TxFetchEvent) -> Result<(), TxFetchError> {
        self.event_tx.send(event).await.map_err(|send_error| {
            TxFetchError::Unavailable(format!("transaction fetcher channel: {send_error}"))
        })
    }

    /// Send an event to the fetcher without blocking the caller.
    ///
    /// For use on the node event loop, where an awaited send could stall the
    /// loop behind a full fetcher channel.
    pub fn try_send(&self, event: TxFetchEvent) -> Result<(), TxFetchError> {
        self.event_tx.try_send(event).map_err(|send_error| {
            TxFetchError::Unavailable(format!("transaction fetcher channel: {send_error}"))
        })
    }

    /// Request a transaction, asking `peer` when given.
    ///
    /// One `GetData::Txid` is in flight per txid. A second `request` for the
    /// same txid joins the existing flight and receives its outcome on its
    /// own oneshot, whichever peer the flight is asking; the wire request is
    /// not repeated. With `None`, an existing flight is joined too; with no
    /// flight, the request resolves with [`TxFetchError::Unavailable`]
    /// because no peer was asked.
    pub async fn request(
        &self,
        txid: Txid,
        peer: Option<PeerId>,
    ) -> Result<oneshot::Receiver<Result<Transaction, TxFetchError>>, TxFetchError> {
        let (responder, response_rx) = oneshot::channel();
        self.send(TxFetchEvent::FetchTransaction {
            txid,
            peer,
            responder,
        })
        .await?;
        Ok(response_rx)
    }
}

/// Receiver half of the transaction fetcher channel.
pub type TxFetchReceiver = mpsc::Receiver<TxFetchEvent>;

/// Create the transaction fetcher event channel.
pub fn create_tx_fetcher_channel() -> (TxFetchHandle, TxFetchReceiver) {
    let (event_tx, event_rx) = mpsc::channel(TX_FETCHER_CHANNEL_CAPACITY);
    (TxFetchHandle { event_tx }, event_rx)
}

/// A pending transaction flight: all callers waiting on one txid while the
/// named peer answers.
struct PendingFlight {
    /// The peer the wire request went to. Only this peer's replies resolve
    /// the flight: in an adversarial network a reply from anyone else proves
    /// nothing.
    peer: Option<PeerId>,
    /// When the wire request was dispatched.
    requested_at: Instant,
    /// Every caller waiting on the flight's outcome.
    responders: Vec<oneshot::Sender<Result<Transaction, TxFetchError>>>,
}

/// Transport-only fetcher correlating transaction requests to their replies.
pub struct TxFetcher {
    event_rx: TxFetchReceiver,
    /// Outbound swarm ops, drained by the actor. The fetcher places its own
    /// `GetData::Txid` requests here, exactly like `BlockFetcher` does.
    swarm_tx: mpsc::Sender<SwarmSend<ResponseChannel<Message>>>,
    /// One entry per txid with an outstanding fetch. Each entry holds every
    /// responder joined onto the flight.
    in_flight: HashMap<Txid, PendingFlight>,
}

impl TxFetcher {
    /// Creates a new transaction fetcher.
    pub fn new(
        event_rx: TxFetchReceiver,
        swarm_tx: mpsc::Sender<SwarmSend<ResponseChannel<Message>>>,
    ) -> Self {
        Self {
            event_rx,
            swarm_tx,
            in_flight: HashMap::with_capacity(INITIAL_IN_FLIGHT_CAPACITY),
        }
    }

    /// Runs the transaction fetcher until the event channel closes. Flights
    /// retire on delivery, on a `NotFound` from the asked peer, on peer
    /// disconnect, and on timeout, each with a distinct result.
    pub async fn run(mut self) {
        info!("Transaction fetcher started");
        let mut tick = tokio::time::interval(TICK_INTERVAL);
        let mut running = true;
        while running {
            tokio::select! {
                event = self.event_rx.recv() => {
                    match event {
                        Some(event) => self.handle_event(event).await,
                        None => running = false,
                    }
                }
                _ = tick.tick() => {
                    self.expire_stale_attempts().await;
                }
            }
        }
        info!("Transaction fetcher stopped -- channel closed");
    }

    async fn handle_event(&mut self, event: TxFetchEvent) {
        match event {
            TxFetchEvent::FetchTransaction {
                txid,
                peer,
                responder,
            } => {
                self.handle_fetch_transaction(txid, peer, responder).await;
            }
            TxFetchEvent::TransactionReceived { peer, transaction } => {
                self.handle_transaction_received(peer, transaction);
            }
            TxFetchEvent::TransactionNotFound { peer, txid } => {
                self.handle_transaction_not_found(peer, txid);
            }
            TxFetchEvent::PeerRemoved(peer) => {
                self.handle_peer_removed(peer);
            }
        }
    }

    /// Join any flight already covering `txid`, or start a new one. A
    /// started flight asks the named peer; with no peer named and no
    /// flight, the caller receives `Unavailable` right away because no
    /// peer has vouched for absence.
    async fn handle_fetch_transaction(
        &mut self,
        txid: Txid,
        peer: Option<PeerId>,
        responder: oneshot::Sender<Result<Transaction, TxFetchError>>,
    ) {
        // Join any in-flight request covering this txid: a second asker
        // receives the same outcome on its own oneshot without repeating
        // the wire request.
        debug!("Transaction fetcher received request for {txid}");
        if let Some(flight) = self.in_flight.get_mut(&txid) {
            debug!("Joining existing in-flight transaction request for {txid}");
            flight.responders.push(responder);
            return;
        }
        //* No peer named: report that the fetch could not be attempted without
        //* claiming the transaction is absent.
        let Some(peer) = peer else {
            debug!("Resolving transaction request for {txid}: no peer to ask");
            let _ = responder.send(Err(TxFetchError::Unavailable(
                "no peer selected".to_owned(),
            )));
            return;
        };
        //* Otherwise record the flight and place the wire request on the
        //* swarm; a closed channel fails the flight rather than stranding
        //* its callers.
        self.in_flight.insert(
            txid,
            PendingFlight {
                peer: Some(peer),
                requested_at: Instant::now(),
                responders: vec![responder],
            },
        );
        if let Err(send_error) = self
            .swarm_tx
            .send(SwarmSend::Request(
                peer,
                Message::GetData(GetData::Txid(txid)),
            ))
            .await
        {
            error!("Failed to dispatch GetData::Txid for {txid} to peer {peer}: {send_error}");
            self.resolve_flight(
                txid,
                Err(TxFetchError::Unavailable(format!(
                    "transaction dispatch channel: {send_error}"
                ))),
            );
        }
    }

    /// Resolve the flight for the transaction's txid when the sending peer
    /// is the one the wire request went to. Anything else is dropped for
    /// now: a transaction's txid self-verifies, but a peer we never asked
    /// proves nothing about who owes the answer.
    fn handle_transaction_received(&mut self, peer: PeerId, transaction: Transaction) {
        let txid = transaction.compute_txid();
        let Some(flight) = self.in_flight.get_mut(&txid) else {
            // TODO: Save to mempool once we have that
            debug!("Dropping unsolicited transaction {txid}");
            return;
        };
        if flight.peer != Some(peer) {
            // TODO: We might want to keep this just in case the other peer times out or fails
            debug!("Ignoring transaction {txid} from {peer}: a different peer was asked for it");
            return;
        }
        debug!("Resolving transaction request for {txid}");
        self.resolve_flight(txid, Ok(transaction));
    }

    /// Resolve the flight with `NotFound` when the answering peer is the one
    /// the wire request went to. A `NotFound` from any other peer proves
    /// nothing in an adversarial network and is ignored.
    fn handle_transaction_not_found(&mut self, peer: PeerId, txid: Txid) {
        let Some(flight) = self.in_flight.get_mut(&txid) else {
            debug!("No in-flight transaction request for {txid}");
            return;
        };
        if flight.peer != Some(peer) {
            debug!("Ignoring notfound for {txid} from {peer}: a different peer was asked for it");
            return;
        }
        debug!("Peer {peer} vouched that {txid} is absent");
        self.resolve_flight(txid, Err(TxFetchError::NotFound));
    }

    /// Resolve every flight waiting on the disconnected peer with an
    /// unavailable error, not an absence verdict.
    fn handle_peer_removed(&mut self, peer: PeerId) {
        let affected: Vec<Txid> = self
            .in_flight
            .iter()
            .filter(|(_, flight)| flight.peer == Some(peer))
            .map(|(txid, _)| *txid)
            .collect();
        for txid in affected {
            debug!("Peer {peer} disconnected, resolving transaction request for {txid}");
            self.resolve_flight(
                txid,
                Err(TxFetchError::Unavailable(
                    "asked peer disconnected".to_owned(),
                )),
            );
        }
    }

    /// Retire flights whose wire request outlived [`REQUEST_TIMEOUT`].
    async fn expire_stale_attempts(&mut self) {
        let expired: Vec<Txid> = self
            .in_flight
            .iter()
            .filter(|(_, flight)| flight.requested_at.elapsed() >= REQUEST_TIMEOUT)
            .map(|(txid, _)| *txid)
            .collect();
        for txid in expired {
            debug!("Transaction request for {txid} timed out");
            self.resolve_flight(
                txid,
                Err(TxFetchError::Unavailable("request timed out".to_owned())),
            );
        }
    }

    /// Deliver `result` to every responder of `txid` and retire the flight.
    fn resolve_flight(&mut self, txid: Txid, result: Result<Transaction, TxFetchError>) {
        let Some(flight) = self.in_flight.remove(&txid) else {
            info!("No in-flight transaction request for {txid}");
            return;
        };
        for responder in flight.responders {
            if responder.send(result.clone()).is_err() {
                debug!("Transaction requester dropped the flight for {txid}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::test_coinbase_transaction;
    use bitcoin::hashes::Hash as _;

    const SWARM_CHANNEL_CAPACITY: usize = 32;

    fn spawn_fetcher() -> (
        TxFetchHandle,
        mpsc::Receiver<SwarmSend<ResponseChannel<Message>>>,
    ) {
        let (tx_fetch_handle, tx_fetch_rx) = create_tx_fetcher_channel();
        let (swarm_tx, swarm_rx) = mpsc::channel(SWARM_CHANNEL_CAPACITY);
        let fetcher = TxFetcher::new(tx_fetch_rx, swarm_tx);
        tokio::spawn(async move { fetcher.run().await });
        (tx_fetch_handle, swarm_rx)
    }

    fn spawn_fetcher_with_dead_swarm() -> TxFetchHandle {
        let (tx_fetch_handle, tx_fetch_rx) = create_tx_fetcher_channel();
        let (swarm_tx, _dead_swarm_rx) =
            mpsc::channel::<SwarmSend<ResponseChannel<Message>>>(SWARM_CHANNEL_CAPACITY);
        drop(_dead_swarm_rx);
        let fetcher = TxFetcher::new(tx_fetch_rx, swarm_tx);
        tokio::spawn(async move { fetcher.run().await });
        tx_fetch_handle
    }

    #[tokio::test]
    async fn test_request_with_peer_emits_dispatch_for_that_peer() {
        let (tx_fetch_handle, mut swarm_rx) = spawn_fetcher();

        let peer = PeerId::random();
        let transaction = test_coinbase_transaction(1);
        let txid = transaction.compute_txid();
        let _response_rx = tx_fetch_handle
            .request(txid, Some(peer))
            .await
            .expect("Failed to send fetch request");

        match swarm_rx.recv().await.unwrap() {
            SwarmSend::Request(dispatch_peer, Message::GetData(GetData::Txid(dispatch_txid))) => {
                assert_eq!(dispatch_peer, peer);
                assert_eq!(dispatch_txid, txid);
            }
            other => panic!("Unexpected swarm send: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_duplicate_request_joins_flight_without_second_dispatch() {
        let (tx_fetch_handle, mut swarm_rx) = spawn_fetcher();

        let peer = PeerId::random();
        let transaction = test_coinbase_transaction(1);
        let txid = transaction.compute_txid();
        let first_rx = tx_fetch_handle
            .request(txid, Some(peer))
            .await
            .expect("Failed to send first fetch request");
        let second_rx = tx_fetch_handle
            .request(txid, Some(peer))
            .await
            .expect("Failed to send second fetch request");

        swarm_rx.recv().await.unwrap();
        assert!(
            swarm_rx.try_recv().is_err(),
            "Duplicate request for one txid produced a second dispatch"
        );

        tx_fetch_handle
            .send(TxFetchEvent::TransactionReceived {
                peer,
                transaction: transaction.clone(),
            })
            .await
            .expect("Failed to send received event");

        assert_eq!(first_rx.await.unwrap().unwrap(), transaction);
        assert_eq!(second_rx.await.unwrap().unwrap(), transaction);
    }

    #[tokio::test]
    async fn test_request_for_different_peer_joins_flight() {
        let (tx_fetch_handle, mut swarm_rx) = spawn_fetcher();

        let asked_peer = PeerId::random();
        let different_peer = PeerId::random();
        let transaction = test_coinbase_transaction(1);
        let txid = transaction.compute_txid();
        let first_rx = tx_fetch_handle
            .request(txid, Some(asked_peer))
            .await
            .expect("Failed to send first fetch request");
        let second_rx = tx_fetch_handle
            .request(txid, Some(different_peer))
            .await
            .expect("Failed to send second fetch request");

        assert!(matches!(
            swarm_rx.recv().await.unwrap(),
            SwarmSend::Request(dispatch_peer, Message::GetData(GetData::Txid(dispatched_txid)))
                if dispatch_peer == asked_peer && dispatched_txid == txid
        ));
        assert!(
            swarm_rx.try_recv().is_err(),
            "Joined request produced a second dispatch"
        );

        tx_fetch_handle
            .send(TxFetchEvent::TransactionReceived {
                peer: asked_peer,
                transaction: transaction.clone(),
            })
            .await
            .expect("Failed to send received event");
        assert_eq!(first_rx.await.unwrap().unwrap(), transaction);
        assert_eq!(second_rx.await.unwrap().unwrap(), transaction);
    }

    #[tokio::test]
    async fn test_request_without_peer_joins_existing_flight() {
        let (tx_fetch_handle, mut swarm_rx) = spawn_fetcher();

        let peer = PeerId::random();
        let transaction = test_coinbase_transaction(1);
        let txid = transaction.compute_txid();
        let first_rx = tx_fetch_handle
            .request(txid, Some(peer))
            .await
            .expect("Failed to send fetch request");
        let joined_rx = tx_fetch_handle
            .request(txid, None)
            .await
            .expect("Failed to send joined fetch request");

        assert!(matches!(
            swarm_rx.recv().await.unwrap(),
            SwarmSend::Request(dispatch_peer, Message::GetData(GetData::Txid(dispatched_txid)))
                if dispatch_peer == peer && dispatched_txid == txid
        ));
        assert!(
            swarm_rx.try_recv().is_err(),
            "Joined request produced a second dispatch"
        );

        tx_fetch_handle
            .send(TxFetchEvent::TransactionReceived {
                peer,
                transaction: transaction.clone(),
            })
            .await
            .expect("Failed to send received event");
        assert_eq!(first_rx.await.unwrap().unwrap(), transaction);
        assert_eq!(joined_rx.await.unwrap().unwrap(), transaction);
    }

    #[tokio::test]
    async fn test_transaction_from_asked_peer_resolves_flight() {
        let (tx_fetch_handle, mut swarm_rx) = spawn_fetcher();

        let peer = PeerId::random();
        let transaction = test_coinbase_transaction(1);
        let txid = transaction.compute_txid();
        let response_rx = tx_fetch_handle
            .request(txid, Some(peer))
            .await
            .expect("Failed to send fetch request");
        swarm_rx.recv().await.unwrap();

        tx_fetch_handle
            .send(TxFetchEvent::TransactionReceived {
                peer,
                transaction: transaction.clone(),
            })
            .await
            .expect("Failed to send received event");

        assert_eq!(response_rx.await.unwrap().unwrap(), transaction);
    }

    #[tokio::test]
    async fn test_unsolicited_transaction_is_dropped_without_panic() {
        let (tx_fetch_handle, tx_fetch_rx) = create_tx_fetcher_channel();
        let (swarm_tx, _swarm_rx) =
            mpsc::channel::<SwarmSend<ResponseChannel<Message>>>(SWARM_CHANNEL_CAPACITY);
        let fetcher_task =
            tokio::spawn(async move { TxFetcher::new(tx_fetch_rx, swarm_tx).run().await });

        let transaction = test_coinbase_transaction(1);
        tx_fetch_handle
            .send(TxFetchEvent::TransactionReceived {
                peer: PeerId::random(),
                transaction: transaction.clone(),
            })
            .await
            .expect("Failed to send received event");
        tx_fetch_handle
            .send(TxFetchEvent::TransactionNotFound {
                peer: PeerId::random(),
                txid: transaction.compute_txid(),
            })
            .await
            .expect("Failed to send not found event");
        drop(tx_fetch_handle);

        // The fetcher observed the dropped transaction and kept running, so
        // it exits cleanly once the handle is gone.
        assert!(
            fetcher_task.await.is_ok(),
            "Fetcher task panicked on unsolicited transaction"
        );
    }

    #[tokio::test]
    async fn test_transaction_from_other_peer_is_ignored() {
        let (tx_fetch_handle, mut swarm_rx) = spawn_fetcher();

        let peer = PeerId::random();
        let other_peer = PeerId::random();
        let transaction = test_coinbase_transaction(1);
        let txid = transaction.compute_txid();
        let mut response_rx = tx_fetch_handle
            .request(txid, Some(peer))
            .await
            .expect("Failed to send fetch request");
        swarm_rx.recv().await.unwrap();

        tx_fetch_handle
            .send(TxFetchEvent::TransactionReceived {
                peer: other_peer,
                transaction: transaction.clone(),
            })
            .await
            .expect("Failed to send received event");
        assert!(
            response_rx.try_recv().is_err(),
            "A different peer's transaction resolved the flight"
        );

        tx_fetch_handle
            .send(TxFetchEvent::TransactionReceived {
                peer,
                transaction: transaction.clone(),
            })
            .await
            .expect("Failed to send received event");
        assert_eq!(response_rx.await.unwrap().unwrap(), transaction);
    }

    #[tokio::test]
    async fn test_not_found_from_asked_peer_resolves_not_found() {
        let (tx_fetch_handle, mut swarm_rx) = spawn_fetcher();

        let peer = PeerId::random();
        let txid = Txid::all_zeros();
        let response_rx = tx_fetch_handle
            .request(txid, Some(peer))
            .await
            .expect("Failed to send fetch request");
        swarm_rx.recv().await.unwrap();

        tx_fetch_handle
            .send(TxFetchEvent::TransactionNotFound { peer, txid })
            .await
            .expect("Failed to send not found event");

        assert_eq!(response_rx.await.unwrap(), Err(TxFetchError::NotFound));
    }

    #[tokio::test]
    async fn test_not_found_from_other_peer_is_ignored() {
        let (tx_fetch_handle, mut swarm_rx) = spawn_fetcher();

        let peer = PeerId::random();
        let other_peer = PeerId::random();
        let txid = Txid::all_zeros();
        let mut response_rx = tx_fetch_handle
            .request(txid, Some(peer))
            .await
            .expect("Failed to send fetch request");
        swarm_rx.recv().await.unwrap();

        tx_fetch_handle
            .send(TxFetchEvent::TransactionNotFound {
                peer: other_peer,
                txid,
            })
            .await
            .expect("Failed to send not found event");
        assert!(
            response_rx.try_recv().is_err(),
            "A different peer's notfound resolved the flight"
        );

        tx_fetch_handle
            .send(TxFetchEvent::TransactionNotFound { peer, txid })
            .await
            .expect("Failed to send not found event");
        assert_eq!(response_rx.await.unwrap(), Err(TxFetchError::NotFound));
    }

    #[tokio::test]
    async fn test_peer_removed_resolves_flight_as_unavailable() {
        let (tx_fetch_handle, mut swarm_rx) = spawn_fetcher();

        let peer = PeerId::random();
        let txid = Txid::all_zeros();
        let response_rx = tx_fetch_handle
            .request(txid, Some(peer))
            .await
            .expect("Failed to send fetch request");
        swarm_rx.recv().await.unwrap();

        tx_fetch_handle
            .send(TxFetchEvent::PeerRemoved(peer))
            .await
            .expect("Failed to send peer removed event");

        assert_eq!(
            response_rx.await.unwrap(),
            Err(TxFetchError::Unavailable(
                "asked peer disconnected".to_owned()
            ))
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_timeout_resolves_flight_as_unavailable() {
        let (tx_fetch_handle, mut swarm_rx) = spawn_fetcher();

        let peer = PeerId::random();
        let txid = Txid::all_zeros();
        let response_rx = tx_fetch_handle
            .request(txid, Some(peer))
            .await
            .expect("Failed to send fetch request");
        swarm_rx.recv().await.unwrap();

        tokio::time::advance(REQUEST_TIMEOUT + TICK_INTERVAL).await;

        assert_eq!(
            response_rx.await.unwrap(),
            Err(TxFetchError::Unavailable("request timed out".to_owned()))
        );
    }

    #[tokio::test]
    async fn test_request_without_peer_resolves_immediately_as_unavailable() {
        let (tx_fetch_handle, mut swarm_rx) = spawn_fetcher();

        let response_rx = tx_fetch_handle
            .request(Txid::all_zeros(), None)
            .await
            .expect("Failed to send fetch request");
        assert!(swarm_rx.try_recv().is_err(), "No peer means no dispatch");
        assert_eq!(
            response_rx.await.unwrap(),
            Err(TxFetchError::Unavailable("no peer selected".to_owned()))
        );
    }

    #[tokio::test]
    async fn test_dispatch_send_failure_resolves_unavailable() {
        let tx_fetch_handle = spawn_fetcher_with_dead_swarm();

        let peer = PeerId::random();
        let txid = Txid::all_zeros();
        let response_rx = tx_fetch_handle
            .request(txid, Some(peer))
            .await
            .expect("Failed to send fetch request");

        assert!(matches!(
            response_rx.await.unwrap(),
            Err(TxFetchError::Unavailable(_))
        ));
    }
}
