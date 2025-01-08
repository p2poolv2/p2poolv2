use p2poolv2::{config::Config, node::actor::NodeHandle};
use std::time::Duration;

#[tokio::test]
async fn test_three_nodes_connectivity() {
    // Create three different configurations as strings

    let config1 = Config::default().with_listen_address("/ip4/0.0.0.0/tcp/6884".to_string()).with_store_path("test_chain_1.db".to_string());
    let config2 = Config::default().with_listen_address("/ip4/0.0.0.0/tcp/6885".to_string()).with_store_path("test_chain_2.db".to_string());
    let config3 = Config::default().with_listen_address("/ip4/0.0.0.0/tcp/6886".to_string()).with_store_path("test_chain_3.db".to_string());
    
    // Start three nodes
    let (node1_handle, stop_rx1) = NodeHandle::new(config1).await.expect("Failed to create node 1");
    let (node2_handle, stop_rx2) = NodeHandle::new(config2).await.expect("Failed to create node 2");
    let (node3_handle, stop_rx3) = NodeHandle::new(config3).await.expect("Failed to create node 3");
    
    // Wait for peer discovery and mesh formation
    tokio::time::sleep(Duration::from_millis(1000)).await;
    
    // Get peer lists from each node
    let peers1 = node1_handle.get_peers().await.expect("Failed to get peers from node 1");
    let peers2 = node2_handle.get_peers().await.expect("Failed to get peers from node 2");
    let peers3 = node3_handle.get_peers().await.expect("Failed to get peers from node 3");
    
    // Assert that each node has exactly two peers
    assert_eq!(peers1.len(), 2, "Node 1 should have 2 peers");
    assert_eq!(peers2.len(), 2, "Node 2 should have 2 peers");
    assert_eq!(peers3.len(), 2, "Node 3 should have 2 peers");
    
    // Clean up
    node1_handle.shutdown().await.expect("Failed to shutdown node 1");
    node2_handle.shutdown().await.expect("Failed to shutdown node 2");
    node3_handle.shutdown().await.expect("Failed to shutdown node 3");
} 