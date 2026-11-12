// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::node::request_response_handler::tx_fetch::{TxFetchEvent, TxFetchHandle};
use bitcoin::Transaction;
use bitcoin::Txid;
use libp2p::PeerId;
use tracing::{debug, error};

/// Forward a transaction received from `peer` to the transaction fetcher.
///
/// The fetcher resolves the transaction against any pending fetch; an
/// unsolicited transaction is acked and dropped for now.
pub async fn handle_transaction_received(
    peer: PeerId,
    transaction: Transaction,
    tx_fetch_handle: &TxFetchHandle,
) {
    let txid = transaction.compute_txid();
    debug!("Received transaction {txid} from peer {peer}");
    if let Err(err) = tx_fetch_handle
        .send(TxFetchEvent::TransactionReceived { peer, transaction })
        .await
    {
        error!(
            "Failed to forward received transaction {txid} to transaction fetcher for peer {peer}: {err}"
        );
    }
}

/// Forward a peer's `NotFound` for `txid` to the transaction fetcher.
pub async fn handle_transaction_not_found(
    peer: PeerId,
    txid: Txid,
    tx_fetch_handle: &TxFetchHandle,
) {
    debug!("Received transaction notfound for {txid} from peer {peer}");
    if let Err(err) = tx_fetch_handle
        .send(TxFetchEvent::TransactionNotFound { peer, txid })
        .await
    {
        error!(
            "Failed to forward transaction notfound for {txid} to transaction fetcher for peer {peer}: {err}"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::request_response_handler::tx_fetch::create_tx_fetcher_channel;
    use crate::test_utils::test_coinbase_transaction;

    #[tokio::test]
    async fn test_handle_transaction_received_forwards_to_fetcher() {
        let (tx_fetch_handle, mut tx_fetch_rx) = create_tx_fetcher_channel();
        let peer = PeerId::random();
        let transaction = test_coinbase_transaction(1);

        handle_transaction_received(peer, transaction.clone(), &tx_fetch_handle).await;

        match tx_fetch_rx.recv().await {
            Some(TxFetchEvent::TransactionReceived {
                peer: event_peer,
                transaction: event_transaction,
            }) => {
                assert_eq!(event_peer, peer);
                assert_eq!(event_transaction, transaction);
            }
            other => panic!("Expected TransactionReceived event, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_handle_transaction_not_found_forwards_to_fetcher() {
        let (tx_fetch_handle, mut tx_fetch_rx) = create_tx_fetcher_channel();
        let peer = PeerId::random();
        let txid = test_coinbase_transaction(1).compute_txid();

        handle_transaction_not_found(peer, txid, &tx_fetch_handle).await;

        match tx_fetch_rx.recv().await {
            Some(TxFetchEvent::TransactionNotFound {
                peer: event_peer,
                txid: event_txid,
            }) => {
                assert_eq!(event_peer, peer);
                assert_eq!(event_txid, txid);
            }
            other => panic!("Expected TransactionNotFound event, got: {other:?}"),
        }
    }
}
