// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Hydrapool PPLNS share worker stores accepted stratum shares for
//! time-window PPLNS payouts in a dedicated task.
//!
//! The stratum connection task only enqueues a share and returns, so it can
//! send the next job to the miner without waiting on the store writer.

use crate::accounting::payout::simple_pplns::SimplePplnsShare;
#[cfg(test)]
#[mockall_double::double]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
#[cfg(not(test))]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
use tokio::sync::mpsc;
use tracing::{error, info};

pub type PplnsShareSender = mpsc::Sender<SimplePplnsShare>;
pub type PplnsShareReceiver = mpsc::Receiver<SimplePplnsShare>;

/// Worker that stores hydrapool PPLNS shares received from the stratum server.
///
/// This is the only path into PPLNS share storage. Every share on the
/// channel is stored and credited at its `difficulty`, so producers must only
/// send shares whose hash meets that difficulty.
pub struct PplnsShareWorker {
    pplns_shares_rx: PplnsShareReceiver,
    chain_store_handle: ChainStoreHandle,
}

impl PplnsShareWorker {
    /// Creates a new PPLNS share worker.
    pub fn new(pplns_shares_rx: PplnsShareReceiver, chain_store_handle: ChainStoreHandle) -> Self {
        Self {
            pplns_shares_rx,
            chain_store_handle,
        }
    }

    /// Runs the worker until every sender has been dropped.
    ///
    /// A failed store write is logged and the worker moves on to the next
    /// share, so one bad write does not stop PPLNS accounting.
    pub async fn run(mut self) {
        info!("PPLNS share worker started");
        while let Some(pplns_share) = self.pplns_shares_rx.recv().await {
            if let Err(error) = self.chain_store_handle.add_pplns_share(pplns_share).await {
                error!("Failed to store PPLNS share: {error}");
            }
        }
        info!("PPLNS share worker stopped - channel closed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::writer::StoreError;
    use std::time::Duration;

    fn build_pplns_share(user_id: u64, nonce: &str) -> SimplePplnsShare {
        SimplePplnsShare::new(
            user_id,
            1000,
            "tb1q3udk7r26qs32ltf9nmqrjaaa7tr55qmkk30q5d".to_string(),
            "worker1".to_string(),
            1700000000,
            "6a".to_string(),
            "00000001".to_string(),
            nonce.to_string(),
        )
    }

    #[tokio::test]
    async fn test_run_stores_received_share() {
        let (pplns_shares_tx, pplns_shares_rx) = mpsc::channel(10);

        let mut mock_chain_store = ChainStoreHandle::default();
        mock_chain_store
            .expect_add_pplns_share()
            .withf(|share| share.user_id == 7 && share.nonce == "e9695791")
            .times(1)
            .returning(|_| Ok(()));

        let worker = PplnsShareWorker::new(pplns_shares_rx, mock_chain_store);
        let worker_handle = tokio::spawn(worker.run());

        pplns_shares_tx
            .send(build_pplns_share(7, "e9695791"))
            .await
            .unwrap();
        drop(pplns_shares_tx);

        tokio::time::timeout(Duration::from_secs(1), worker_handle)
            .await
            .expect("worker should stop after the sender is dropped")
            .unwrap();
    }

    #[tokio::test]
    async fn test_run_continues_after_store_error() {
        let (pplns_shares_tx, pplns_shares_rx) = mpsc::channel(10);

        let mut mock_chain_store = ChainStoreHandle::default();
        mock_chain_store
            .expect_add_pplns_share()
            .withf(|share| share.nonce == "00000001")
            .times(1)
            .returning(|_| Err(StoreError::ChannelClosed));
        mock_chain_store
            .expect_add_pplns_share()
            .withf(|share| share.nonce == "00000002")
            .times(1)
            .returning(|_| Ok(()));

        let worker = PplnsShareWorker::new(pplns_shares_rx, mock_chain_store);
        let worker_handle = tokio::spawn(worker.run());

        pplns_shares_tx
            .send(build_pplns_share(1, "00000001"))
            .await
            .unwrap();
        pplns_shares_tx
            .send(build_pplns_share(1, "00000002"))
            .await
            .unwrap();
        drop(pplns_shares_tx);

        tokio::time::timeout(Duration::from_secs(1), worker_handle)
            .await
            .expect("worker should stop after the sender is dropped")
            .unwrap();
    }

    #[tokio::test]
    async fn test_run_exits_when_sender_dropped() {
        let (pplns_shares_tx, pplns_shares_rx) = mpsc::channel(10);

        let mut mock_chain_store = ChainStoreHandle::default();
        mock_chain_store.expect_add_pplns_share().times(0);

        let worker = PplnsShareWorker::new(pplns_shares_rx, mock_chain_store);
        let worker_handle = tokio::spawn(worker.run());

        drop(pplns_shares_tx);

        tokio::time::timeout(Duration::from_secs(1), worker_handle)
            .await
            .expect("worker should stop after the sender is dropped")
            .unwrap();
    }
}
