// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use bitcoin::hashes::Hash as _;
use p2poolv2_lib::accounting::stats::metrics;
use p2poolv2_lib::monitoring_events::create_monitoring_event_channel;
use p2poolv2_lib::node::request_response_handler::tx_fetch::TxFetchError;
use p2poolv2_lib::shares::chain::chain_store_handle::ChainStoreHandle;
use p2poolv2_lib::shares::share_block::ShareBlock;
use p2poolv2_lib::store::Store;
use p2poolv2_lib::store::writer::{StoreHandle, StoreWriter, write_channel};
use p2poolv2_lib::stratum::emission::Emission;
use p2poolv2_lib::stratum::work::notify::NotifyCmd;
use p2poolv2_lib::{node::actor::NodeHandle, test_utils::TestShareBlockBuilder};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tempfile::tempdir;

use crate::common;

const PEER_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const PEER_CONNECT_POLL: Duration = Duration::from_millis(100);

/// Node A serves a share-chain transaction it holds in its confirmed store
/// when node B asks for it over the wire, and answers an unknown txid with
/// NotFound.
#[test_log::test(tokio::test)]
async fn test_two_nodes_fetch_transaction_over_wire() {
    // Process-unique ports below the Linux ephemeral range: fixed ports
    // collide with the previous run's sockets in TIME_WAIT when this test
    // is rerun in isolation, and Linux hands out ephemeral ports from
    // 32768 up.
    let port_a = 20_000 + (std::process::id() % 12_000) as u16;
    let port_b = port_a + 1;

    let config_a = common::default_test_config()
        .with_listen_address(format!("/ip4/127.0.0.1/tcp/{port_a}"))
        .with_store_path("fetch_test_chain_a.db".to_string());
    let config_b = common::default_test_config()
        .with_listen_address(format!("/ip4/127.0.0.1/tcp/{port_b}"))
        .with_store_path("fetch_test_chain_b.db".to_string())
        .with_dial_peers(vec![format!("/ip4/127.0.0.1/tcp/{port_a}")]);

    let temp_dir_a = tempdir().unwrap();
    let temp_dir_b = tempdir().unwrap();

    let store_a =
        Arc::new(Store::new(temp_dir_a.path().to_str().unwrap().to_string(), false).unwrap());
    let (write_tx_a, write_rx_a) = write_channel();
    let store_writer_a = StoreWriter::new(store_a.clone(), write_rx_a);
    tokio::task::spawn_blocking(move || store_writer_a.run());
    let store_handle_a = StoreHandle::new(store_a, write_tx_a);
    let chain_store_handle_a = ChainStoreHandle::new(store_handle_a, config_a.stratum.network());
    let genesis_a = ShareBlock::build_genesis_for_network(config_a.stratum.chain).unwrap();
    chain_store_handle_a
        .init_or_setup_genesis(genesis_a.clone())
        .await
        .unwrap();

    // Seed node A's confirmed chain with a share block carrying the known
    // transaction so get_tx can reconstruct it by txid.
    let known_transaction = p2poolv2_lib::test_utils::test_coinbase_transaction(1);
    let known_txid = known_transaction.compute_txid();
    let seeded_share = TestShareBlockBuilder::new()
        .prev_share_blockhash(genesis_a.block_hash().to_string())
        .add_transaction(known_transaction.clone())
        .build();
    chain_store_handle_a
        .add_share_block(seeded_share)
        .await
        .unwrap();

    let store_b =
        Arc::new(Store::new(temp_dir_b.path().to_str().unwrap().to_string(), false).unwrap());
    let (write_tx_b, write_rx_b) = write_channel();
    let store_writer_b = StoreWriter::new(store_b.clone(), write_rx_b);
    tokio::task::spawn_blocking(move || store_writer_b.run());
    let store_handle_b = StoreHandle::new(store_b, write_tx_b);
    let chain_store_handle_b = ChainStoreHandle::new(store_handle_b, config_b.stratum.network());
    chain_store_handle_b
        .init_or_setup_genesis(
            ShareBlock::build_genesis_for_network(config_b.stratum.chain).unwrap(),
        )
        .await
        .unwrap();

    let (_shares_tx_a, shares_rx_a) = tokio::sync::mpsc::channel::<Emission>(10);
    let (_shares_tx_b, shares_rx_b) = tokio::sync::mpsc::channel::<Emission>(10);

    let stats_dir_a = tempfile::tempdir().unwrap();
    let stats_dir_b = tempfile::tempdir().unwrap();
    let metrics_a = metrics::start_metrics(stats_dir_a.path().to_str().unwrap().to_string())
        .await
        .unwrap();
    let metrics_b = metrics::start_metrics(stats_dir_b.path().to_str().unwrap().to_string())
        .await
        .unwrap();

    let monitoring_tx_a = create_monitoring_event_channel();
    let (notify_tx_a, _notify_rx_a) = tokio::sync::mpsc::channel::<NotifyCmd>(10);
    let (_node_a, _stop_rx_a) = NodeHandle::new(
        config_a,
        chain_store_handle_a,
        shares_rx_a,
        metrics_a,
        monitoring_tx_a,
        notify_tx_a,
        Arc::new(RwLock::new(
            p2poolv2_lib::accounting::payout::sharechain_pplns::PplnsWindow::new(
                bitcoin::Network::Signet,
            ),
        )),
    )
    .await
    .expect("Failed to create node A");

    let monitoring_tx_b = create_monitoring_event_channel();
    let (notify_tx_b, _notify_rx_b) = tokio::sync::mpsc::channel::<NotifyCmd>(10);
    let (node_b, _stop_rx_b) = NodeHandle::new(
        config_b,
        chain_store_handle_b,
        shares_rx_b,
        metrics_b,
        monitoring_tx_b,
        notify_tx_b,
        Arc::new(RwLock::new(
            p2poolv2_lib::accounting::payout::sharechain_pplns::PplnsWindow::new(
                bitcoin::Network::Signet,
            ),
        )),
    )
    .await
    .expect("Failed to create node B");

    // Wait for node B to connect to node A.
    let started = std::time::Instant::now();
    let peer_a = loop {
        let peers = node_b
            .get_peers()
            .await
            .expect("Failed to get peers from node B");
        if let Some(peer_a) = peers.first().copied() {
            break peer_a;
        }
        assert!(
            started.elapsed() < PEER_CONNECT_TIMEOUT,
            "Node B never connected to node A within {PEER_CONNECT_TIMEOUT:?}"
        );
        tokio::time::sleep(PEER_CONNECT_POLL).await;
    };

    let served = node_b
        .request_transaction(known_txid, Some(peer_a))
        .await
        .expect("Node B did not resolve the fetched transaction");

    assert_eq!(
        served, known_transaction,
        "Node B received a different transaction than node A holds"
    );

    let unknown_txid = bitcoin::Txid::all_zeros();
    let unknown = node_b.request_transaction(unknown_txid, Some(peer_a)).await;

    assert_eq!(
        unknown,
        Err(TxFetchError::NotFound),
        "Node A must answer an unknown txid with NotFound"
    );

    node_b.shutdown().await.expect("Failed to shut down node B");
}
