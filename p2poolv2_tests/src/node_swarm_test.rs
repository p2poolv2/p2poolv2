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

use p2poolv2_lib::accounting::payout::sharechain_pplns::PplnsWindow;
use p2poolv2_lib::accounting::stats::metrics;
use p2poolv2_lib::monitoring_events::create_monitoring_event_channel;
use p2poolv2_lib::shares::chain::chain_store_handle::ChainStoreHandle;
use p2poolv2_lib::store::Store;
use p2poolv2_lib::store::writer::{StoreHandle, StoreWriter, write_channel};
use p2poolv2_lib::stratum::emission::Emission;
use p2poolv2_lib::stratum::work::notify::NotifyCmd;
use p2poolv2_lib::{node::actor::NodeHandle, shares::share_block::ShareBlock};
use std::sync::{Arc, RwLock};

use std::time::Duration;
use tempfile::tempdir;

use crate::common;

#[test_log::test(tokio::test)]
async fn test_three_nodes_connectivity() {
    // Create three different configurations as strings

    let config1 = common::default_test_config()
        .with_listen_address("/ip4/127.0.0.1/tcp/7884".to_string())
        .with_store_path("test_chain_1.db".to_string());
    let config2 = common::default_test_config()
        .with_listen_address("/ip4/127.0.0.1/tcp/7885".to_string())
        .with_store_path("test_chain_2.db".to_string())
        .with_dial_peers(vec!["/ip4/127.0.0.1/tcp/7884".to_string()]);
    let config3 = common::default_test_config()
        .with_listen_address("/ip4/127.0.0.1/tcp/7886".to_string())
        .with_store_path("test_chain_3.db".to_string())
        .with_dial_peers(vec![
            "/ip4/127.0.0.1/tcp/7884".to_string(),
            "/ip4/127.0.0.1/tcp/7885".to_string(),
        ]);

    let temp_dir1 = tempdir().unwrap();
    let temp_dir2 = tempdir().unwrap();
    let temp_dir3 = tempdir().unwrap();

    // Setup store 1 with StoreWriter and ChainStoreHandle
    let store1 =
        Arc::new(Store::new(temp_dir1.path().to_str().unwrap().to_string(), false).unwrap());
    let (write_tx1, write_rx1) = write_channel();
    let store_writer1 = StoreWriter::new(store1.clone(), write_rx1);
    tokio::task::spawn_blocking(move || store_writer1.run());
    let store_handle1 = StoreHandle::new(store1, write_tx1);
    let chain_store_handle1 = ChainStoreHandle::new(store_handle1, config1.stratum.network);
    chain_store_handle1
        .init_or_setup_genesis(
            ShareBlock::build_genesis_for_network(config1.stratum.network).unwrap(),
        )
        .await
        .unwrap();

    // Setup store 2 with StoreWriter and ChainStoreHandle
    let store2 =
        Arc::new(Store::new(temp_dir2.path().to_str().unwrap().to_string(), false).unwrap());
    let (write_tx2, write_rx2) = write_channel();
    let store_writer2 = StoreWriter::new(store2.clone(), write_rx2);
    tokio::task::spawn_blocking(move || store_writer2.run());
    let store_handle2 = StoreHandle::new(store2, write_tx2);
    let chain_store_handle2 = ChainStoreHandle::new(store_handle2, config2.stratum.network);
    chain_store_handle2
        .init_or_setup_genesis(
            ShareBlock::build_genesis_for_network(config2.stratum.network).unwrap(),
        )
        .await
        .unwrap();

    // Setup store 3 with StoreWriter and ChainStoreHandle
    let store3 =
        Arc::new(Store::new(temp_dir3.path().to_str().unwrap().to_string(), false).unwrap());
    let (write_tx3, write_rx3) = write_channel();
    let store_writer3 = StoreWriter::new(store3.clone(), write_rx3);
    tokio::task::spawn_blocking(move || store_writer3.run());
    let store_handle3 = StoreHandle::new(store3, write_tx3);
    let chain_store_handle3 = ChainStoreHandle::new(store_handle3, config3.stratum.network);
    chain_store_handle3
        .init_or_setup_genesis(
            ShareBlock::build_genesis_for_network(config3.stratum.network).unwrap(),
        )
        .await
        .unwrap();

    let (_shares_tx_1, shares_rx_1) = tokio::sync::mpsc::channel::<Emission>(10);
    let (_shares_tx_2, shares_rx_2) = tokio::sync::mpsc::channel::<Emission>(10);
    let (_shares_tx_3, shares_rx_3) = tokio::sync::mpsc::channel::<Emission>(10);

    let stats_dir1 = tempfile::tempdir().unwrap();
    let stats_dir2 = tempfile::tempdir().unwrap();
    let stats_dir3 = tempfile::tempdir().unwrap();
    let metrics1 = metrics::start_metrics(stats_dir1.path().to_str().unwrap().to_string())
        .await
        .unwrap();
    let metrics2 = metrics::start_metrics(stats_dir2.path().to_str().unwrap().to_string())
        .await
        .unwrap();
    let metrics3 = metrics::start_metrics(stats_dir3.path().to_str().unwrap().to_string())
        .await
        .unwrap();

    // Start three nodes
    let (monitoring_tx1, _monitoring_rx1) = create_monitoring_event_channel();
    let (notify_tx1, _notify_rx1) = tokio::sync::mpsc::channel::<NotifyCmd>(10);
    let (node1_handle, _stop_rx1) = NodeHandle::new(
        config1,
        chain_store_handle1,
        shares_rx_1,
        metrics1,
        monitoring_tx1,
        notify_tx1,
        Arc::new(RwLock::new(PplnsWindow::new(bitcoin::Network::Signet))),
    )
    .await
    .expect("Failed to create node 1");
    tokio::time::sleep(Duration::from_millis(300)).await;
    let (monitoring_tx2, _monitoring_rx2) = create_monitoring_event_channel();
    let (notify_tx2, _notify_rx2) = tokio::sync::mpsc::channel::<NotifyCmd>(10);
    let (node2_handle, _stop_rx2) = NodeHandle::new(
        config2,
        chain_store_handle2,
        shares_rx_2,
        metrics2,
        monitoring_tx2,
        notify_tx2,
        Arc::new(RwLock::new(PplnsWindow::new(bitcoin::Network::Signet))),
    )
    .await
    .expect("Failed to create node 2");
    tokio::time::sleep(Duration::from_millis(300)).await;
    let (monitoring_tx3, _monitoring_rx3) = create_monitoring_event_channel();
    let (notify_tx3, _notify_rx3) = tokio::sync::mpsc::channel::<NotifyCmd>(10);
    let (node3_handle, _stop_rx3) = NodeHandle::new(
        config3,
        chain_store_handle3,
        shares_rx_3,
        metrics3,
        monitoring_tx3,
        notify_tx3,
        Arc::new(RwLock::new(PplnsWindow::new(bitcoin::Network::Signet))),
    )
    .await
    .expect("Failed to create node 3");
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Get peer lists from each node
    let peers1 = node1_handle
        .get_peers()
        .await
        .expect("Failed to get peers from node 1");
    let peers2 = node2_handle
        .get_peers()
        .await
        .expect("Failed to get peers from node 2");
    let peers3 = node3_handle
        .get_peers()
        .await
        .expect("Failed to get peers from node 3");

    // Assert that each node has exactly two peers
    assert_eq!(peers1.len(), 2, "Node 1 should have 2 peers");
    assert_eq!(peers2.len(), 2, "Node 2 should have 2 peers");
    assert_eq!(peers3.len(), 2, "Node 3 should have 2 peers");

    // Clean up
    node1_handle
        .shutdown()
        .await
        .expect("Failed to shutdown node 1");
    node2_handle
        .shutdown()
        .await
        .expect("Failed to shutdown node 2");
    node3_handle
        .shutdown()
        .await
        .expect("Failed to shutdown node 3");
}

/// Load share blocks from the share_sync fixture file.
///
/// Returns a vector of ShareBlock ordered by chain height (genesis first).
fn load_share_sync_blocks() -> Vec<ShareBlock> {
    let json_string = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("test_data/share_sync/share_blocks.json"),
    )
    .expect("Failed to read share_blocks fixture");
    serde_json::from_str(&json_string).expect("Failed to parse share_blocks fixture")
}

/// Test that shares seeded on one node sync to two other nodes via p2p.
///
/// Node 1 is seeded with 5 real share headers (from store.db fixture) before
/// nodes 2 and 3 start. Nodes 2 and 3 dial into node 1 and should sync all
/// shares via the header-sync and block-fetch protocol.
#[test_log::test(tokio::test)]
async fn test_three_nodes_share_sync() {
    let fixture_blocks = load_share_sync_blocks();
    let share_count = (fixture_blocks.len() - 1) as u32;
    // Configure three nodes on unique ports with higher rate limit for fast sync
    // Pool signature must match the cluster config that generated the fixture blocks
    let pool_signature = Some("P2Poolv2".to_string());
    let config1 = common::default_test_config()
        .with_listen_address("/ip4/127.0.0.1/tcp/6894".to_string())
        .with_store_path("test_sync_chain_1.db".to_string())
        .with_max_requests_per_second(100)
        .with_pool_signature(pool_signature.clone())
        .with_api_port(3010);
    let config2 = common::default_test_config()
        .with_listen_address("/ip4/127.0.0.1/tcp/6895".to_string())
        .with_store_path("test_sync_chain_2.db".to_string())
        .with_max_requests_per_second(100)
        .with_pool_signature(pool_signature.clone())
        .with_api_port(3011)
        .with_dial_peers(vec!["/ip4/127.0.0.1/tcp/6894".to_string()]);
    let config3 = common::default_test_config()
        .with_listen_address("/ip4/127.0.0.1/tcp/6896".to_string())
        .with_store_path("test_sync_chain_3.db".to_string())
        .with_max_requests_per_second(100)
        .with_pool_signature(pool_signature)
        .with_api_port(3012)
        .with_dial_peers(vec!["/ip4/127.0.0.1/tcp/6894".to_string()]);

    let temp_dir1 = tempdir().unwrap();
    let temp_dir2 = tempdir().unwrap();
    let temp_dir3 = tempdir().unwrap();

    // Setup store 1 and seed with shares
    let store1 =
        Arc::new(Store::new(temp_dir1.path().to_str().unwrap().to_string(), false).unwrap());
    let (write_tx1, write_rx1) = write_channel();
    let store_writer1 = StoreWriter::new(store1.clone(), write_rx1);
    tokio::task::spawn_blocking(move || store_writer1.run());
    let store_handle1 = StoreHandle::new(store1, write_tx1);
    let chain_store_handle1 = ChainStoreHandle::new(store_handle1, config1.stratum.network);

    // Load genesis from fixture and seed into store 1
    let genesis = fixture_blocks[0].clone();
    chain_store_handle1
        .init_or_setup_genesis(genesis.clone())
        .await
        .unwrap();

    // Seed non-genesis shares from fixture into store 1
    for share_block in &fixture_blocks[1..] {
        chain_store_handle1
            .add_share_block(share_block.clone())
            .await
            .unwrap();
        chain_store_handle1
            .organise_header(share_block.header.clone())
            .await
            .unwrap();
        chain_store_handle1.organise_block().await.unwrap();
    }

    // Verify node 1 has all shares
    let tip_height1 = chain_store_handle1.get_tip_height().unwrap();
    assert_eq!(
        tip_height1,
        Some(share_count),
        "Node 1 should have {share_count} shares after seeding"
    );

    // Setup store 2 with only genesis
    let store2 =
        Arc::new(Store::new(temp_dir2.path().to_str().unwrap().to_string(), false).unwrap());
    let (write_tx2, write_rx2) = write_channel();
    let store_writer2 = StoreWriter::new(store2.clone(), write_rx2);
    tokio::task::spawn_blocking(move || store_writer2.run());
    let store_handle2 = StoreHandle::new(store2, write_tx2);
    let chain_store_handle2 = ChainStoreHandle::new(store_handle2, config2.stratum.network);
    chain_store_handle2
        .init_or_setup_genesis(genesis.clone())
        .await
        .unwrap();

    // Setup store 3 with only genesis
    let store3 =
        Arc::new(Store::new(temp_dir3.path().to_str().unwrap().to_string(), false).unwrap());
    let (write_tx3, write_rx3) = write_channel();
    let store_writer3 = StoreWriter::new(store3.clone(), write_rx3);
    tokio::task::spawn_blocking(move || store_writer3.run());
    let store_handle3 = StoreHandle::new(store3, write_tx3);
    let chain_store_handle3 = ChainStoreHandle::new(store_handle3, config3.stratum.network);
    chain_store_handle3
        .init_or_setup_genesis(genesis.clone())
        .await
        .unwrap();

    // Clone chain store handles for polling after node creation
    let chain_store_handle1_poll = chain_store_handle1.clone();
    let chain_store_handle2_poll = chain_store_handle2.clone();
    let chain_store_handle3_poll = chain_store_handle3.clone();

    let (_shares_tx_1, shares_rx_1) = tokio::sync::mpsc::channel::<Emission>(10);
    let (_shares_tx_2, shares_rx_2) = tokio::sync::mpsc::channel::<Emission>(10);
    let (_shares_tx_3, shares_rx_3) = tokio::sync::mpsc::channel::<Emission>(10);

    let stats_dir1 = tempfile::tempdir().unwrap();
    let stats_dir2 = tempfile::tempdir().unwrap();
    let stats_dir3 = tempfile::tempdir().unwrap();
    let metrics1 = metrics::start_metrics(stats_dir1.path().to_str().unwrap().to_string())
        .await
        .unwrap();
    let metrics2 = metrics::start_metrics(stats_dir2.path().to_str().unwrap().to_string())
        .await
        .unwrap();
    let metrics3 = metrics::start_metrics(stats_dir3.path().to_str().unwrap().to_string())
        .await
        .unwrap();

    // Start node 1 (seeded with shares)
    let (monitoring_tx1, _monitoring_rx1) = create_monitoring_event_channel();
    let (notify_tx1, _notify_rx1) = tokio::sync::mpsc::channel::<NotifyCmd>(10);
    let (node1_handle, _stop_rx1) = NodeHandle::new(
        config1,
        chain_store_handle1,
        shares_rx_1,
        metrics1,
        monitoring_tx1,
        notify_tx1,
        Arc::new(RwLock::new(PplnsWindow::new(bitcoin::Network::Signet))),
    )
    .await
    .expect("Failed to create node 1");
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Start nodes 2 and 3 (they dial into node 1 and should sync)
    let (monitoring_tx2, _monitoring_rx2) = create_monitoring_event_channel();
    let (notify_tx2, _notify_rx2) = tokio::sync::mpsc::channel::<NotifyCmd>(10);
    let (node2_handle, _stop_rx2) = NodeHandle::new(
        config2,
        chain_store_handle2,
        shares_rx_2,
        metrics2,
        monitoring_tx2,
        notify_tx2,
        Arc::new(RwLock::new(PplnsWindow::new(bitcoin::Network::Signet))),
    )
    .await
    .expect("Failed to create node 2");
    let (monitoring_tx3, _monitoring_rx3) = create_monitoring_event_channel();
    let (notify_tx3, _notify_rx3) = tokio::sync::mpsc::channel::<NotifyCmd>(10);
    let (node3_handle, _stop_rx3) = NodeHandle::new(
        config3,
        chain_store_handle3,
        shares_rx_3,
        metrics3,
        monitoring_tx3,
        notify_tx3,
        Arc::new(RwLock::new(PplnsWindow::new(bitcoin::Network::Signet))),
    )
    .await
    .expect("Failed to create node 3");

    // Poll until both nodes reach the expected tip height
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut synced = false;
    while tokio::time::Instant::now() < deadline {
        let height2 = chain_store_handle2_poll.get_tip_height().unwrap();
        let height3 = chain_store_handle3_poll.get_tip_height().unwrap();
        if height2 == Some(share_count) && height3 == Some(share_count) {
            synced = true;
            break; // intentional: exit polling loop on success
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    assert!(
        synced,
        "Timed out waiting for sync: node2={:?}, node3={:?}",
        chain_store_handle2_poll.get_tip_height(),
        chain_store_handle3_poll.get_tip_height()
    );

    // Verify all three nodes have identical confirmed chains
    let chain1 = chain_store_handle1_poll
        .get_confirmed_headers_in_range(0, share_count)
        .expect("Failed to get confirmed headers from node 1");
    let chain2 = chain_store_handle2_poll
        .get_confirmed_headers_in_range(0, share_count)
        .expect("Failed to get confirmed headers from node 2");
    let chain3 = chain_store_handle3_poll
        .get_confirmed_headers_in_range(0, share_count)
        .expect("Failed to get confirmed headers from node 3");

    assert_eq!(
        chain1.len(),
        chain2.len(),
        "Node 1 and node 2 have different chain lengths"
    );
    assert_eq!(
        chain1.len(),
        chain3.len(),
        "Node 1 and node 3 have different chain lengths"
    );

    for index in 0..chain1.len() {
        assert_eq!(
            chain1[index].blockhash, chain2[index].blockhash,
            "Chain mismatch at index {index}: node1={}, node2={}",
            chain1[index].blockhash, chain2[index].blockhash
        );
        assert_eq!(
            chain1[index].blockhash, chain3[index].blockhash,
            "Chain mismatch at index {index}: node1={}, node3={}",
            chain1[index].blockhash, chain3[index].blockhash
        );
        assert_eq!(
            chain1[index].height, chain2[index].height,
            "Height mismatch at index {index}: node1={}, node2={}",
            chain1[index].height, chain2[index].height
        );
    }

    // Clean up
    node1_handle
        .shutdown()
        .await
        .expect("Failed to shutdown node 1");
    node2_handle
        .shutdown()
        .await
        .expect("Failed to shutdown node 2");
    node3_handle
        .shutdown()
        .await
        .expect("Failed to shutdown node 3");
}
