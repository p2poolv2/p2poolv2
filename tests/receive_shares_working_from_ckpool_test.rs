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

mod common;

mod zmq_tests {
    use super::common::default_test_config;
    use p2poolv2::node::actor::NodeHandle;
    use p2poolv2::shares::chain::ChainHandle;
    use p2poolv2::shares::miner_message::CkPoolMessage;
    use std::fs;
    use std::time::Duration;
    use tempfile;
    use tempfile::tempdir;
    use zmq;

    #[tokio::test]
    async fn test_single_node_with_zmq_feed_of_workbases_only() {
        tracing::info!("Starting test_single_node_with_zmq_feed");

        // Create configuration for a single node
        let config = default_test_config()
            .with_listen_address("/ip4/0.0.0.0/tcp/6887".to_string())
            .with_store_path("test_chain_zmq.db".to_string())
            .with_miner_pubkey(
                "020202020202020202020202020202020202020202020202020202020202020202".to_string(),
            );

        let temp_dir = tempdir().unwrap();
        let chain_handle = ChainHandle::new(temp_dir.path().to_str().unwrap().to_string());

        // Start the node
        let (node_handle, _stop_rx) = NodeHandle::new(config.clone(), chain_handle.clone())
            .await
            .expect("Failed to create node");

        // Load test data from JSON file
        let test_data = fs::read_to_string("tests/test_data/workbases_only.json")
            .expect("Failed to read test data file");

        // Start ZMQ publishing socket
        let ctx = zmq::Context::new();
        let publisher = ctx
            .socket(zmq::PUB)
            .expect("Failed to create ZMQ PUB socket");
        publisher
            .bind(format!("tcp://*:{}", config.ckpool.port).as_str())
            .expect("Failed to bind ZMQ socket");

        // Give the node time to start up
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Deserialize into MinerMessage array
        let ckpool_messages: Vec<CkPoolMessage> =
            serde_json::from_str(&test_data).expect("Failed to deserialize test data");

        // Publish each message from test data
        for message in ckpool_messages {
            let serialized = serde_json::to_string(&message).unwrap();
            tracing::debug!("Publishing message: {:?}", &message);
            publisher
                .send(&serialized, 0)
                .expect("Failed to publish message");

            // Small delay between messages to avoid overwhelming the system
            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        let workbase = chain_handle
            .get_workbase(7460801854683742211)
            .await
            .unwrap();
        assert_eq!(workbase.gbt.height, 109);

        let workbase = chain_handle
            .get_workbase(7460801854683742212)
            .await
            .unwrap();
        assert_eq!(workbase.gbt.height, 109);

        // Clean up
        node_handle
            .shutdown()
            .await
            .expect("Failed to shutdown node");
    }

    #[tokio::test]
    async fn test_single_node_with_zmq_feed_of_shares_only() {
        tracing::info!("Starting test_single_node_with_zmq_feed");

        let config = default_test_config()
            .with_listen_address("/ip4/0.0.0.0/tcp/6888".to_string())
            .with_store_path("test_chain_zmq.db".to_string())
            .with_ckpool_port(8882)
            .with_miner_pubkey(
                "020202020202020202020202020202020202020202020202020202020202020202".to_string(),
            );

        let temp_dir = tempdir().unwrap();
        let chain_handle = ChainHandle::new(temp_dir.path().to_str().unwrap().to_string());

        // Start the node
        let (node_handle, _stop_rx) = NodeHandle::new(config.clone(), chain_handle.clone())
            .await
            .expect("Failed to create node");

        // Load test data from JSON file
        let test_data = fs::read_to_string("tests/test_data/shares_only.json")
            .expect("Failed to read test data file");

        // Start ZMQ publishing socket
        let ctx = zmq::Context::new();
        let publisher = ctx
            .socket(zmq::PUB)
            .expect("Failed to create ZMQ PUB socket");
        publisher
            .bind(format!("tcp://*:{}", config.ckpool.port).as_str())
            .expect("Failed to bind ZMQ socket");

        // Give the node time to start up
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Deserialize into MinerMessage array
        let ckpool_messages: Vec<CkPoolMessage> =
            serde_json::from_str(&test_data).expect("Failed to deserialize test data");

        // Publish each message from test data
        for message in ckpool_messages {
            let serialized = serde_json::to_string(&message).unwrap();
            tracing::debug!("Publishing message: {:?}", &message);
            publisher
                .send(&serialized, 0)
                .expect("Failed to publish message");

            // Small delay between messages to avoid overwhelming the system
            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        // Verify the node received and processed the data
        assert!(chain_handle
            .get_share(
                "00000000debd331503c0e5348801a2057d2b8c8b96dcfb075d5a283954846172"
                    .parse()
                    .unwrap()
            )
            .await
            .is_some());
        assert!(chain_handle
            .get_share(
                "00000000debd331503c0e5348801a2057d2b8c8b96dcfb075d5a283954846173"
                    .parse()
                    .unwrap()
            )
            .await
            .is_some());

        let workbase = chain_handle.get_workbase(7460801854683742211).await;
        assert!(workbase.is_none());

        // Clean up
        node_handle
            .shutdown()
            .await
            .expect("Failed to shutdown node");
    }

    #[tokio::test]
    async fn test_single_node_with_shares_and_workbases() {
        tracing::info!("Starting test_single_node_with_shares_and_workbases");

        // Create configuration for a single node
        let config = default_test_config()
            .with_listen_address("/ip4/0.0.0.0/tcp/6889".to_string())
            .with_store_path("test_chain_zmq.db".to_string())
            .with_ckpool_port(8883)
            .with_miner_pubkey(
                "020202020202020202020202020202020202020202020202020202020202020202".to_string(),
            );

        let temp_dir = tempdir().unwrap();
        let chain_handle = ChainHandle::new(temp_dir.path().to_str().unwrap().to_string());

        // Start the node
        let (node_handle, _stop_rx) = NodeHandle::new(config.clone(), chain_handle.clone())
            .await
            .expect("Failed to create node");

        // Load test data from JSON file
        let test_data = fs::read_to_string("tests/test_data/single_node_simple.json")
            .expect("Failed to read test data file");

        // Start ZMQ publishing socket
        let ctx = zmq::Context::new();
        let publisher = ctx
            .socket(zmq::PUB)
            .expect("Failed to create ZMQ PUB socket");
        publisher
            .bind(format!("tcp://*:{}", config.ckpool.port).as_str())
            .expect("Failed to bind ZMQ socket");

        // Give the node time to start up
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Deserialize into MinerMessage array
        let ckpool_messages: Vec<CkPoolMessage> =
            serde_json::from_str(&test_data).expect("Failed to deserialize test data");

        // Publish each message from test data
        for message in ckpool_messages {
            let serialized = serde_json::to_string(&message).unwrap();
            tracing::debug!("Publishing message: {:?}", &message);
            publisher
                .send(&serialized, 0)
                .expect("Failed to publish message");

            // Small delay between messages to avoid overwhelming the system
            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        // Verify the node received and processed the data
        assert!(chain_handle
            .get_share(
                "00000000debd331503c0e5348801a2057d2b8c8b96dcfb075d5a283954846172"
                    .parse()
                    .unwrap()
            )
            .await
            .is_some());

        let workbase = chain_handle
            .get_workbase(7460801854683742211)
            .await
            .unwrap();
        assert_eq!(workbase.gbt.height, 109);

        // Clean up
        node_handle
            .shutdown()
            .await
            .expect("Failed to shutdown node");
    }
}
