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

//! Emission worker processes stratum share submissions in a dedicated task.
//!
//! This offloads CPU-intensive merkle tree calculations from the main swarm
//! event loop, improving P2P responsiveness. Storage is delegated to the
//! ChainStoreHandle for serialized database writes.

use crate::node::SwarmSend;
use crate::node::messages::Message;
use crate::node::organise_worker::{OrganiseEvent, OrganiseSender};
#[cfg(test)]
#[mockall_double::double]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
#[cfg(not(test))]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
use crate::shares::handle_stratum_share::handle_stratum_share;
use crate::stratum::emission::{Emission, EmissionReceiver};
use libp2p::request_response::ResponseChannel;
use tokio::sync::mpsc;
use tracing::{debug, error, info};

/// Type alias for the swarm sender used by the emission worker.
type SwarmSender = mpsc::Sender<SwarmSend<ResponseChannel<Message>>>;

/// Worker that processes emissions from the stratum server.
///
/// Runs in a separate tokio task to avoid blocking the main swarm event loop
/// during CPU-intensive share processing operations.
pub struct EmissionWorker {
    emissions_rx: EmissionReceiver,
    swarm_tx: SwarmSender,
    chain_store_handle: ChainStoreHandle,
    network: bitcoin::Network,
    organise_tx: OrganiseSender,
}

impl EmissionWorker {
    /// Creates a new emission worker.
    pub fn new(
        emissions_rx: EmissionReceiver,
        swarm_tx: SwarmSender,
        chain_store_handle: ChainStoreHandle,
        network: bitcoin::Network,
        organise_tx: OrganiseSender,
    ) -> Self {
        Self {
            emissions_rx,
            swarm_tx,
            chain_store_handle,
            network,
            organise_tx,
        }
    }

    /// Runs the emission worker until the emissions channel is closed.
    pub async fn run(mut self) {
        info!("Emission worker started");
        while let Some(emission) = self.emissions_rx.recv().await {
            debug!("Processing emission");
            // Pass a reference to chain store handle to avoid clones on each loop
            match handle_stratum_share(emission, &self.chain_store_handle).await {
                Ok(Some(share_block)) => {
                    // Send block to organise worker for confirmed promotion.
                    if let Err(e) = self
                        .organise_tx
                        .send(OrganiseEvent::Block(share_block.clone()))
                        .await
                    {
                        error!("Failed to send block to organise worker: {e}");
                    }
                    // Announce block to peers via inventory message
                    let block_hash = share_block.block_hash();
                    if let Err(e) = self.swarm_tx.send(SwarmSend::Inv(block_hash)).await {
                        error!("Failed to queue inv for block {block_hash}: {e}");
                    }
                }
                Ok(None) => {
                    // PPLNS-only share (p2p disabled), no broadcast needed
                }
                Err(e) => {
                    error!("Error processing emission: {e}");
                }
            }
        }
        info!("Emission worker stopped - channel closed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounting::payout::simple_pplns::SimplePplnsShare;
    use crate::node::organise_worker::create_organise_channel;
    use crate::shares::extranonce::Extranonce;
    use crate::store::writer::StoreError;
    use crate::stratum::work::block_template::BlockTemplate;
    use crate::test_utils::{TEST_COINBASE_NSECS, create_test_commitment};
    use bitcoin::block::Header;
    use bitcoin::hashes::Hash;
    use bitcoin::{BlockHash, CompactTarget};
    use bitcoin::{Transaction, absolute::LockTime, transaction::Version};
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Duration;

    fn create_test_blocktemplate() -> BlockTemplate {
        BlockTemplate {
            version: 0x20000000,
            rules: vec![],
            vbavailable: HashMap::with_capacity(0),
            vbrequired: 0,
            previousblockhash: "0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
            transactions: vec![],
            coinbaseaux: HashMap::with_capacity(0),
            coinbasevalue: 5000000000,
            longpollid: String::new(),
            target: "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            mintime: 0,
            mutable: vec![],
            noncerange: "00000000ffffffff".to_string(),
            sigoplimit: 80000,
            sizelimit: 4000000,
            weightlimit: 4000000,
            curtime: 1700000000,
            bits: "207fffff".to_string(),
            height: 1,
            default_witness_commitment: None,
        }
    }

    fn create_test_emission_without_commitment() -> Emission {
        let pplns = SimplePplnsShare {
            user_id: 1,
            difficulty: 1000,
            btcaddress: Some("tb1qtest".to_string()),
            workername: Some("worker1".to_string()),
            n_time: 1700000000,
            job_id: "test_job_1".to_string(),
            extranonce2: "00000001".to_string(),
            nonce: "12345".to_string(),
        };

        let bitcoin_header = Header {
            version: bitcoin::block::Version::TWO,
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time: 1700000000,
            bits: CompactTarget::from_consensus(0x1b4188f5),
            nonce: 12345,
        };

        let coinbase = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![],
        };

        Emission {
            pplns,
            header: bitcoin_header,
            coinbase,
            blocktemplate: Arc::new(create_test_blocktemplate()),
            share_commitment: None,
            coinbase_nsecs: TEST_COINBASE_NSECS,
            template_merkle_branches: vec![],
            extranonce: Extranonce::default(),
        }
    }

    fn create_test_emission_with_commitment() -> Emission {
        let pplns = SimplePplnsShare {
            user_id: 1,
            difficulty: 1000,
            btcaddress: Some("tb1qtest".to_string()),
            workername: Some("worker1".to_string()),
            n_time: 1700000000,
            job_id: "test_job_1".to_string(),
            extranonce2: "00000001".to_string(),
            nonce: "12345".to_string(),
        };

        let bitcoin_header = Header {
            version: bitcoin::block::Version::TWO,
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time: 1700000000,
            bits: CompactTarget::from_consensus(0x1b4188f5),
            nonce: 12345,
        };

        let coinbase = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![],
        };

        let commitment = create_test_commitment();

        Emission {
            pplns,
            header: bitcoin_header,
            coinbase,
            blocktemplate: Arc::new(create_test_blocktemplate()),
            share_commitment: Some(commitment),
            coinbase_nsecs: TEST_COINBASE_NSECS,
            template_merkle_branches: vec![],
            extranonce: Extranonce::default(),
        }
    }

    #[tokio::test]
    async fn test_run_with_p2p_share_sends_organise_and_inv() {
        let (emissions_tx, emissions_rx) = mpsc::channel::<Emission>(10);
        let (swarm_tx, mut swarm_rx) = mpsc::channel::<SwarmSend<ResponseChannel<Message>>>(10);
        let (organise_tx, mut organise_rx) = create_organise_channel();

        let mut mock_chain_store = ChainStoreHandle::default();
        mock_chain_store
            .expect_add_share_block()
            .returning(|_| Ok(()));

        let worker = EmissionWorker::new(
            emissions_rx,
            swarm_tx,
            mock_chain_store,
            bitcoin::Network::Regtest,
            organise_tx,
        );
        let worker_handle = tokio::spawn(worker.run());

        emissions_tx
            .send(create_test_emission_with_commitment())
            .await
            .unwrap();
        drop(emissions_tx);

        let organise_event = tokio::time::timeout(Duration::from_secs(2), organise_rx.recv()).await;
        assert!(
            matches!(organise_event, Ok(Some(OrganiseEvent::Block(_)))),
            "Expected OrganiseEvent::Block"
        );

        let swarm_event = tokio::time::timeout(Duration::from_secs(2), swarm_rx.recv()).await;
        assert!(
            matches!(swarm_event, Ok(Some(SwarmSend::Inv(_)))),
            "Expected SwarmSend::Inv"
        );

        worker_handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_run_without_commitment_sends_nothing() {
        let (emissions_tx, emissions_rx) = mpsc::channel::<Emission>(10);
        let (swarm_tx, mut swarm_rx) = mpsc::channel::<SwarmSend<ResponseChannel<Message>>>(10);
        let (organise_tx, mut organise_rx) = create_organise_channel();

        let mut mock_chain_store = ChainStoreHandle::default();
        mock_chain_store
            .expect_add_pplns_share()
            .returning(|_| Ok(()));

        let worker = EmissionWorker::new(
            emissions_rx,
            swarm_tx,
            mock_chain_store,
            bitcoin::Network::Regtest,
            organise_tx,
        );
        let worker_handle = tokio::spawn(worker.run());

        emissions_tx
            .send(create_test_emission_without_commitment())
            .await
            .unwrap();
        drop(emissions_tx);

        worker_handle.await.unwrap();

        assert!(
            organise_rx.try_recv().is_err(),
            "No OrganiseEvent expected for PPLNS-only share"
        );
        assert!(
            swarm_rx.try_recv().is_err(),
            "No SwarmSend expected for PPLNS-only share"
        );
    }

    #[tokio::test]
    async fn test_run_continues_after_handle_error() {
        let (emissions_tx, emissions_rx) = mpsc::channel::<Emission>(10);
        let (swarm_tx, mut swarm_rx) = mpsc::channel::<SwarmSend<ResponseChannel<Message>>>(10);
        let (organise_tx, mut organise_rx) = create_organise_channel();

        let mut mock_chain_store = ChainStoreHandle::default();
        // First call fails, second call succeeds
        mock_chain_store
            .expect_add_pplns_share()
            .times(1)
            .returning(|_| Err(StoreError::ChannelClosed));
        mock_chain_store
            .expect_add_share_block()
            .times(1)
            .returning(|_| Ok(()));

        let worker = EmissionWorker::new(
            emissions_rx,
            swarm_tx,
            mock_chain_store,
            bitcoin::Network::Regtest,
            organise_tx,
        );
        let worker_handle = tokio::spawn(worker.run());

        // First emission: error path (no commitment, store fails)
        emissions_tx
            .send(create_test_emission_without_commitment())
            .await
            .unwrap();
        // Second emission: success path (with commitment, store succeeds)
        emissions_tx
            .send(create_test_emission_with_commitment())
            .await
            .unwrap();
        drop(emissions_tx);

        worker_handle.await.unwrap();

        // Only the second emission should produce organise + inv events
        assert!(
            matches!(organise_rx.try_recv(), Ok(OrganiseEvent::Block(_))),
            "Expected OrganiseEvent::Block from second emission"
        );
        assert!(
            matches!(swarm_rx.try_recv(), Ok(SwarmSend::Inv(_))),
            "Expected SwarmSend::Inv from second emission"
        );

        assert!(
            organise_rx.try_recv().is_err(),
            "No more organise events expected"
        );
        assert!(
            swarm_rx.try_recv().is_err(),
            "No more swarm events expected"
        );
    }

    #[tokio::test]
    async fn test_run_stops_when_channel_closes() {
        let (emissions_tx, emissions_rx) = mpsc::channel::<Emission>(10);
        let (swarm_tx, _swarm_rx) = mpsc::channel::<SwarmSend<ResponseChannel<Message>>>(10);
        let (organise_tx, _organise_rx) = create_organise_channel();

        let mock_chain_store = ChainStoreHandle::default();

        let worker = EmissionWorker::new(
            emissions_rx,
            swarm_tx,
            mock_chain_store,
            bitcoin::Network::Regtest,
            organise_tx,
        );
        let worker_handle = tokio::spawn(worker.run());

        drop(emissions_tx);

        let result = tokio::time::timeout(Duration::from_secs(2), worker_handle).await;
        assert!(
            result.is_ok(),
            "Worker should stop promptly when channel closes"
        );
    }
}
