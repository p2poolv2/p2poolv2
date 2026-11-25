// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::node::Message;
use crate::node::SwarmSend;
use crate::node::messages::GetData;
#[cfg(test)]
#[mockall_double::double]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
#[cfg(not(test))]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
use crate::store::writer::StoreError;
use bitcoin::BlockHash;
use std::error::Error;
use tokio::sync::mpsc;
use tracing::debug;

/// Handle a GetData::Block request from a peer.
///
/// Looks up the requested block and responds with the full ShareBlock if
/// found. The block may not yet be confirmed or even on the candidate
/// chain, but the peer needs it to build its own chain view.
pub async fn handle_getdata_block<C: Send + Sync>(
    block_hash: BlockHash,
    chain_store_handle: ChainStoreHandle,
    response_channel: C,
    swarm_tx: mpsc::Sender<SwarmSend<C>>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    debug!("Received GetData::Block request for {}", block_hash);

    let response_message = match chain_store_handle.get_share(&block_hash) {
        Some(share_block) => {
            debug!("Serving block {} to peer", block_hash);
            Message::ShareBlock(share_block)
        }
        None => {
            debug!("Block {} not found, sending notfound", block_hash);
            Message::NotFound(GetData::Block(block_hash))
        }
    };

    if let Err(err) = swarm_tx
        .send(SwarmSend::Response(response_channel, response_message))
        .await
    {
        tracing::error!("Failed to send getdata block response: {}", err);
        return Err(format!("Failed to send getdata block response: {err}").into());
    }
    Ok(())
}

/// Handle a GetData::Txid request from a peer.
///
/// Serves the transaction from the store, which holds the transactions of
/// every persisted share body, confirmed or not. A store error other than
/// not-found is propagated to the peer service, which treats it as fatal and
/// disconnects the requesting peer.
pub async fn handle_getdata_tx<C: Send + Sync>(
    txid: bitcoin::Txid,
    chain_store_handle: ChainStoreHandle,
    response_channel: C,
    swarm_tx: mpsc::Sender<SwarmSend<C>>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    debug!("Received GetData::Txid request for {}", txid);

    let response_message = match chain_store_handle.get_tx(&txid) {
        Ok(transaction) => {
            debug!("Serving transaction {} to peer", txid);
            Message::Transaction(transaction)
        }
        Err(StoreError::NotFound(_)) => {
            debug!("Transaction {} not found, sending notfound", txid);
            Message::NotFound(GetData::Txid(txid))
        }
        Err(store_error) => {
            tracing::error!("Failed to look up transaction {txid}: {store_error}");
            return Err(format!("Failed to look up transaction {txid}: {store_error}").into());
        }
    };

    if let Err(err) = swarm_tx
        .send(SwarmSend::Response(response_channel, response_message))
        .await
    {
        tracing::error!("Failed to send getdata transaction response: {}", err);
        return Err(format!("Failed to send getdata transaction response: {err}").into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[mockall_double::double]
    use crate::shares::chain::chain_store_handle::ChainStoreHandle;
    use crate::store::writer::StoreError;
    use crate::test_utils::{TestShareBlockBuilder, test_coinbase_transaction};
    use bitcoin::hashes::Hash as _;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_handle_getdata_block_found() {
        let (swarm_tx, mut swarm_rx) = mpsc::channel::<SwarmSend<u32>>(1);
        let response_channel = 1u32;
        let mut chain_store_handle = ChainStoreHandle::default();

        let block = TestShareBlockBuilder::new().build();
        let block_hash = block.block_hash();
        let expected_block = block.clone();

        chain_store_handle
            .expect_get_share()
            .returning(move |_| Some(block.clone()));

        let result =
            handle_getdata_block(block_hash, chain_store_handle, response_channel, swarm_tx).await;

        assert!(result.is_ok());

        if let Some(SwarmSend::Response(channel, Message::ShareBlock(share_block))) =
            swarm_rx.recv().await
        {
            assert_eq!(channel, response_channel);
            assert_eq!(share_block, expected_block);
        } else {
            panic!("Expected SwarmSend::Response with ShareBlock message");
        }
    }

    #[tokio::test]
    async fn test_handle_getdata_block_not_found() {
        let (swarm_tx, mut swarm_rx) = mpsc::channel::<SwarmSend<u32>>(1);
        let response_channel = 1u32;
        let mut chain_store_handle = ChainStoreHandle::default();

        let block_hash = "0000000000000000000000000000000000000000000000000000000000000001"
            .parse::<BlockHash>()
            .unwrap();

        chain_store_handle.expect_get_share().returning(|_| None);

        let result =
            handle_getdata_block(block_hash, chain_store_handle, response_channel, swarm_tx).await;

        assert!(result.is_ok());

        if let Some(SwarmSend::Response(channel, Message::NotFound(GetData::Block(hash)))) =
            swarm_rx.recv().await
        {
            assert_eq!(channel, response_channel);
            assert_eq!(hash, block_hash);
        } else {
            panic!("Expected SwarmSend::Response with NotFound message");
        }
    }

    #[tokio::test]
    async fn test_handle_getdata_block_send_failure() {
        let (swarm_tx, swarm_rx) = mpsc::channel::<SwarmSend<u32>>(1);
        let response_channel = 1u32;
        let mut chain_store_handle = ChainStoreHandle::default();

        let block_hash = "0000000000000000000000000000000000000000000000000000000000000001"
            .parse::<BlockHash>()
            .unwrap();

        chain_store_handle.expect_get_share().returning(|_| None);

        // Drop receiver to cause send failure
        drop(swarm_rx);

        let result =
            handle_getdata_block(block_hash, chain_store_handle, response_channel, swarm_tx).await;

        assert!(result.is_err());
        if let Err(error) = result {
            assert!(
                error
                    .to_string()
                    .contains("Failed to send getdata block response")
            );
        }
    }

    #[tokio::test]
    async fn test_handle_getdata_tx_serves_confirmed_transaction() {
        let (swarm_tx, mut swarm_rx) = mpsc::channel::<SwarmSend<u32>>(1);
        let response_channel = 1u32;
        let mut chain_store_handle = ChainStoreHandle::default();

        let transaction = test_coinbase_transaction(1);
        let txid = transaction.compute_txid();

        chain_store_handle
            .expect_get_tx()
            .returning(move |_| Ok(transaction.clone()));

        let result = handle_getdata_tx(txid, chain_store_handle, response_channel, swarm_tx).await;

        assert!(result.is_ok());

        if let Some(SwarmSend::Response(channel, Message::Transaction(served))) =
            swarm_rx.recv().await
        {
            assert_eq!(channel, response_channel);
            assert_eq!(served.compute_txid(), txid);
        } else {
            panic!("Expected SwarmSend::Response with Transaction message");
        }
    }

    #[tokio::test]
    async fn test_handle_getdata_tx_sends_notfound_when_unknown() {
        let (swarm_tx, mut swarm_rx) = mpsc::channel::<SwarmSend<u32>>(1);
        let response_channel = 1u32;
        let mut chain_store_handle = ChainStoreHandle::default();

        let txid = bitcoin::Txid::all_zeros();

        chain_store_handle
            .expect_get_tx()
            .returning(|txid| Err(StoreError::NotFound(format!("no tx {txid}"))));

        let result = handle_getdata_tx(txid, chain_store_handle, response_channel, swarm_tx).await;

        assert!(result.is_ok());

        if let Some(SwarmSend::Response(channel, Message::NotFound(GetData::Txid(found)))) =
            swarm_rx.recv().await
        {
            assert_eq!(channel, response_channel);
            assert_eq!(found, txid);
        } else {
            panic!("Expected SwarmSend::Response with NotFound message");
        }
    }

    #[tokio::test]
    async fn test_handle_getdata_tx_store_error_propagates() {
        let (swarm_tx, mut swarm_rx) = mpsc::channel::<SwarmSend<u32>>(1);
        let response_channel = 1u32;
        let mut chain_store_handle = ChainStoreHandle::default();

        let txid = bitcoin::Txid::all_zeros();
        chain_store_handle
            .expect_get_tx()
            .returning(|_| Err(StoreError::Database("disk on fire".to_string())));

        let result = handle_getdata_tx(txid, chain_store_handle, response_channel, swarm_tx).await;

        assert!(result.is_err());
        assert!(
            swarm_rx.try_recv().is_err(),
            "A store error must not answer the peer with NotFound"
        );
    }
}
