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
use p2poolv2_lib::{node::actor::NodeHandle, shares::share_block::ShareBlock};
use std::sync::Arc;

use std::time::Duration;
use tempfile::tempdir;

use libp2p::PeerId;
use std::error::Error;
use std::time::Instant;

use crate::common;

async fn wait_for_peers(
    handle: &NodeHandle,
    expected: usize,
    timeout: Duration,
) -> Result<Vec<PeerId>, Box<dyn Error + Send + Sync>> {
    let start = Instant::now();
    loop {
        let peers = handle.get_peers().await?;
        if peers.len() >= expected {
            return Ok(peers);
        }
        if start.elapsed() > timeout {
            return Err(format!(
                "Timed out waiting for peers (expected {expected}, got {}): {peers:?}",
                peers.len()
            )
            .into());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

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

    // Get peer lists from each node (wait until expected peers are connected)
    let peers1 = wait_for_peers(&node1_handle, 2, Duration::from_secs(5))
        .await
        .expect("Node 1 failed to connect to peers");
    let peers2 = wait_for_peers(&node2_handle, 2, Duration::from_secs(5))
        .await
        .expect("Node 2 failed to connect to peers");
    let peers3 = wait_for_peers(&node3_handle, 2, Duration::from_secs(5))
        .await
        .expect("Node 3 failed to connect to peers");

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
