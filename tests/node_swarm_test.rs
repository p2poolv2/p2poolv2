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

mod common;

use p2poolv2_lib::{
    node::actor::NodeHandle,
    shares::{chain::actor::ChainHandle, ShareBlock},
};
use stratum::share_block::StratumShare;

use std::time::Duration;
use tempfile::tempdir;

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

    let chain_handle1 = ChainHandle::new(
        temp_dir1.path().to_str().unwrap().to_string(),
        ShareBlock::build_genesis_for_network(config1.stratum.network),
    );
    let chain_handle2 = ChainHandle::new(
        temp_dir2.path().to_str().unwrap().to_string(),
        ShareBlock::build_genesis_for_network(config2.stratum.network),
    );
    let chain_handle3 = ChainHandle::new(
        temp_dir3.path().to_str().unwrap().to_string(),
        ShareBlock::build_genesis_for_network(config3.stratum.network),
    );

    let (_shares_tx_1, shares_rx_1) = tokio::sync::mpsc::channel::<StratumShare>(10);
    let (_shares_tx_2, shares_rx_2) = tokio::sync::mpsc::channel::<StratumShare>(10);
    let (_shares_tx_3, shares_rx_3) = tokio::sync::mpsc::channel::<StratumShare>(10);

    // Start three nodes
    let (node1_handle, _stop_rx1) = NodeHandle::new(config1, chain_handle1, shares_rx_1)
        .await
        .expect("Failed to create node 1");
    tokio::time::sleep(Duration::from_millis(300)).await;
    let (node2_handle, _stop_rx2) = NodeHandle::new(config2, chain_handle2, shares_rx_2)
        .await
        .expect("Failed to create node 2");
    tokio::time::sleep(Duration::from_millis(300)).await;
    let (node3_handle, _stop_rx3) = NodeHandle::new(config3, chain_handle3, shares_rx_3)
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
