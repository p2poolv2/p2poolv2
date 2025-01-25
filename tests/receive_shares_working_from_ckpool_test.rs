// Copyright (C) 2024 [Kulpreet Singh]
//
//  This file is part of P2Poolv2
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

mod zmq_tests {
    use p2poolv2::shares::miner_message::CkPoolMessage;
    use p2poolv2::{config::Config, node::actor::NodeHandle, shares::chain::ChainHandle};
    use serde_json::json;
    use std::fs;
    use std::time::Duration;
    use tempfile::tempdir;
    use zmq;

    #[test_log::test(tokio::test)]
    async fn test_single_node_with_zmq_feed() {
        tracing::info!("Starting test_single_node_with_zmq_feed");
        // Load test data from JSON file
        let test_data = fs::read_to_string("tests/test_data/single_node_simple.json")
            .expect("Failed to read test data file");

        // Set up ZMQ publisher
        let ctx = zmq::Context::new();
        let publisher = ctx
            .socket(zmq::PUB)
            .expect("Failed to create ZMQ PUB socket");
        publisher
            .bind("tcp://*:8881")
            .expect("Failed to bind ZMQ socket");

        // Give the node time to start up
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Create configuration for a single node
        let config = Config::default()
            .with_listen_address("/ip4/0.0.0.0/tcp/6887".to_string())
            .with_store_path("test_chain_zmq.db".to_string());

        let temp_dir = tempdir().unwrap();
        let chain_handle = ChainHandle::new(temp_dir.path().to_str().unwrap().to_string());

        // Start the node
        let (node_handle, _stop_rx) = NodeHandle::new(config, chain_handle.clone())
            .await
            .expect("Failed to create node");

        // Deserialize into MinerMessage array
        let ckpool_messages: Vec<CkPoolMessage> =
            serde_json::from_str(&test_data).expect("Failed to deserialize test data");

        // Publish each message from test data
        for message in ckpool_messages {
            let serialized = serde_json::to_string(&message).unwrap();
            publisher
                .send(&serialized, 0)
                .expect("Failed to publish message");

            // Small delay between messages to avoid overwhelming the system
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // Give some time for shares to be processed
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Verify the node received and processed the data
        // You might want to add specific verification logic here depending on your implementation
        let tip = chain_handle.get_tip().await.unwrap();
        assert_eq!(
            tip,
            hex::decode("00000000debd331503c0e5348801a2057d2b8c8b96dcfb075d5a283954846172")
                .unwrap()
        );

        // Clean up
        node_handle
            .shutdown()
            .await
            .expect("Failed to shutdown node");
    }
}
