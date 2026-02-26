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

use p2poolv2_lib::accounting::stats::metrics;
use p2poolv2_lib::shares::chain::chain_store_handle::ChainStoreHandle;
use p2poolv2_lib::store::Store;
use p2poolv2_lib::store::writer::{StoreHandle, StoreWriter, write_channel};
use p2poolv2_lib::stratum::emission::Emission;
use p2poolv2_lib::test_utils::TestShareBlockBuilder;
use p2poolv2_lib::{node::actor::NodeHandle, shares::share_block::ShareBlock};
use std::sync::Arc;

use std::time::Duration;
use tempfile::tempdir;

use crate::common;

#[tokio::test]
async fn test_three_nodes_connectivity() {
    // Create three different configurations as strings

    let config1 = common::default_test_config()
        .with_listen_address("/ip4/127.0.0.1/tcp/6884".to_string())
        .with_store_path("test_chain_1.db".to_string())
        .with_miner_pubkey(
            "020202020202020202020202020202020202020202020202020202020202020202".to_string(),
        );
    let config2 = common::default_test_config()
        .with_listen_address("/ip4/127.0.0.1/tcp/6885".to_string())
        .with_store_path("test_chain_2.db".to_string())
        .with_miner_pubkey(
            "020202020202020202020202020202020202020202020202020202020202020202".to_string(),
        )
        .with_dial_peers(vec!["/ip4/127.0.0.1/tcp/6884".to_string()]);
    let config3 = common::default_test_config()
        .with_listen_address("/ip4/127.0.0.1/tcp/6886".to_string())
        .with_store_path("test_chain_3.db".to_string())
        .with_miner_pubkey(
            "020202020202020202020202020202020202020202020202020202020202020202".to_string(),
        )
        .with_dial_peers(vec![
            "/ip4/127.0.0.1/tcp/6884".to_string(),
            "/ip4/127.0.0.1/tcp/6885".to_string(),
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
        .init_or_setup_genesis(ShareBlock::build_genesis_for_network(
            config1.stratum.network,
        ))
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
        .init_or_setup_genesis(ShareBlock::build_genesis_for_network(
            config2.stratum.network,
        ))
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
        .init_or_setup_genesis(ShareBlock::build_genesis_for_network(
            config3.stratum.network,
        ))
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
    let (node1_handle, _stop_rx1) =
        NodeHandle::new(config1, chain_store_handle1, shares_rx_1, metrics1)
            .await
            .expect("Failed to create node 1");
    tokio::time::sleep(Duration::from_millis(300)).await;
    let (node2_handle, _stop_rx2) =
        NodeHandle::new(config2, chain_store_handle2, shares_rx_2, metrics2)
            .await
            .expect("Failed to create node 2");
    tokio::time::sleep(Duration::from_millis(300)).await;
    let (node3_handle, _stop_rx3) =
        NodeHandle::new(config3, chain_store_handle3, shares_rx_3, metrics3)
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

/// Test that shares seeded on one node sync to two other nodes via p2p.
///
/// Node 1 is seeded with 50 shares before nodes 2 and 3 start. Nodes 2
/// and 3 dial into node 1 and should sync all 50 shares via the header-sync
/// and block-fetch protocol.
#[tokio::test]
async fn test_three_nodes_share_sync() {
    const SHARE_COUNT: u32 = 50;
    const MINER_PUBKEY: &str = "020202020202020202020202020202020202020202020202020202020202020202";

    // Configure three nodes on unique ports with higher rate limit for fast sync
    let config1 = common::default_test_config()
        .with_listen_address("/ip4/127.0.0.1/tcp/6894".to_string())
        .with_store_path("test_sync_chain_1.db".to_string())
        .with_miner_pubkey(MINER_PUBKEY.to_string())
        .with_max_requests_per_second(100)
        .with_api_port(3010);
    let config2 = common::default_test_config()
        .with_listen_address("/ip4/127.0.0.1/tcp/6895".to_string())
        .with_store_path("test_sync_chain_2.db".to_string())
        .with_miner_pubkey(MINER_PUBKEY.to_string())
        .with_max_requests_per_second(100)
        .with_api_port(3011)
        .with_dial_peers(vec!["/ip4/127.0.0.1/tcp/6894".to_string()]);
    let config3 = common::default_test_config()
        .with_listen_address("/ip4/127.0.0.1/tcp/6896".to_string())
        .with_store_path("test_sync_chain_3.db".to_string())
        .with_miner_pubkey(MINER_PUBKEY.to_string())
        .with_max_requests_per_second(100)
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

    let genesis = ShareBlock::build_genesis_for_network(config1.stratum.network);
    chain_store_handle1
        .init_or_setup_genesis(genesis.clone())
        .await
        .unwrap();

    // Seed 50 shares chained from genesis
    let mut prev_hash = genesis.block_hash();
    for index in 1..=SHARE_COUNT {
        let share = TestShareBlockBuilder::new()
            .prev_share_blockhash(prev_hash.to_string())
            .nonce(index)
            .build();
        let share_hash = share.block_hash();
        chain_store_handle1
            .add_share_block(share.clone(), true)
            .await
            .unwrap();
        chain_store_handle1
            .organise_header(share.header.clone())
            .await
            .unwrap();
        chain_store_handle1.organise_block().await.unwrap();
        prev_hash = share_hash;
    }

    // Verify node 1 has all shares
    let tip_height1 = chain_store_handle1.get_tip_height().unwrap();
    assert_eq!(
        tip_height1,
        Some(SHARE_COUNT),
        "Node 1 should have {SHARE_COUNT} shares after seeding"
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
        .init_or_setup_genesis(ShareBlock::build_genesis_for_network(
            config2.stratum.network,
        ))
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
        .init_or_setup_genesis(ShareBlock::build_genesis_for_network(
            config3.stratum.network,
        ))
        .await
        .unwrap();

    // Clone chain store handles for polling after node creation
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
    let (node1_handle, _stop_rx1) =
        NodeHandle::new(config1, chain_store_handle1, shares_rx_1, metrics1)
            .await
            .expect("Failed to create node 1");
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Start nodes 2 and 3 (they dial into node 1 and should sync)
    let (node2_handle, _stop_rx2) =
        NodeHandle::new(config2, chain_store_handle2, shares_rx_2, metrics2)
            .await
            .expect("Failed to create node 2");
    let (node3_handle, _stop_rx3) =
        NodeHandle::new(config3, chain_store_handle3, shares_rx_3, metrics3)
            .await
            .expect("Failed to create node 3");

    // Poll until both nodes reach the expected tip height
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut synced = false;
    while tokio::time::Instant::now() < deadline {
        let height2 = chain_store_handle2_poll.get_tip_height().unwrap();
        let height3 = chain_store_handle3_poll.get_tip_height().unwrap();
        if height2 == Some(SHARE_COUNT) && height3 == Some(SHARE_COUNT) {
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
