// Copyright (C) 2024, 2025 P2Poolv2 Developers (see AUTHORS)
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

mod self_and_peer_messages_tests {
    use super::common::{default_test_config, simple_miner_workbase};
    use p2poolv2_lib::node::actor::NodeHandle;
    use p2poolv2_lib::node::messages::Message;
    use p2poolv2_lib::node::p2p_message_handlers::handle_request_with_service;
    use p2poolv2_lib::shares::chain::actor::ChainHandle;
    use p2poolv2_lib::shares::miner_message::CkPoolMessage;
    use p2poolv2_lib::shares::ShareBlock;
    use p2poolv2_lib::utils::time_provider::{SystemTimeProvider, TestTimeProvider, TimeProvider};
    use std::fs;
    use std::time::{Duration, SystemTime};
    use tempfile::tempdir;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn receive_shares_and_workbases_from_self_and_peers() {
        // Create config for a single node
        let config = default_test_config()
            .with_listen_address("/ip4/127.0.0.1/tcp/6890".to_string())
            .with_ckpool_port(8885)
            .with_store_path("test_chain_zmq.db".to_string())
            .with_miner_pubkey(
                "020202020202020202020202020202020202020202020202020202020202020202".to_string(),
            );

        let temp_dir = tempdir().unwrap();
        let chain_handle = ChainHandle::new(
            temp_dir.path().to_str().unwrap().to_string(),
            ShareBlock::build_genesis_for_network(config.bitcoin.network),
        );

        // Start the node
        let (node_handle, _stop_rx) = NodeHandle::new(config.clone(), chain_handle.clone())
            .await
            .expect("Failed to create node");

        let ckpool_data = fs::read_to_string("tests/test_data/self_shares_and_workbases.json")
            .expect("Failed to read CKPool test data file");

        let peer_data = fs::read_to_string("tests/test_data/peer_shares_and_workbases.json")
            .expect("Failed to read peer test data file");

        let ckpool_messages: Vec<CkPoolMessage> =
            serde_json::from_str(&ckpool_data).expect("Failed to deserialize CKPool data");
        let peer_ckpool_messages: Vec<CkPoolMessage> =
            serde_json::from_str(&peer_data).expect("Failed to deserialize peer data");

        let peer_messages: Vec<Message> = peer_ckpool_messages
            .into_iter()
            .map(|msg| match msg {
                CkPoolMessage::Share(share) => {
                    let pubkey =
                        "020202020202020202020202020202020202020202020202020202020202020203"
                            .parse()
                            .unwrap();
                    let mut peer_share =
                        ShareBlock::new(share, pubkey, bitcoin::Network::Regtest, &mut vec![]);
                    // set all peer shares to have the no prev_share_blockhash
                    peer_share.header.prev_share_blockhash = None;
                    Message::ShareBlock(peer_share)
                }
                CkPoolMessage::Workbase(workbase) => Message::Workbase(workbase),
                CkPoolMessage::UserWorkbase(userworkbase) => Message::UserWorkbase(userworkbase),
            })
            .collect();

        let ctx = zmq::Context::new();
        let publisher = ctx
            .socket(zmq::PUB)
            .expect("Failed to create ZMQ PUB socket");
        publisher
            .bind(format!("tcp://*:{}", config.ckpool.port).as_str())
            .expect("Failed to bind ZMQ socket");

        tokio::time::sleep(Duration::from_millis(500)).await;

        let ckpool_iter = ckpool_messages.iter();
        let peer_iter = peer_messages.iter();
        let peer_id = libp2p::PeerId::random();
        let (swarm_tx, mut swarm_rx) = mpsc::channel(100);
        let (response_channel_tx, _response_channel_rx) = mpsc::channel::<Message>(100);
        tokio::spawn(async move {
            while (swarm_rx.recv().await).is_some() {
                tracing::debug!("Received swarm send");
            }
        });

        for ckpool_msg in ckpool_iter {
            let serialized = serde_json::to_string(&ckpool_msg).unwrap();
            publisher
                .send(&serialized, 0)
                .expect("Failed to publish message");
        }

        tokio::time::sleep(Duration::from_millis(100)).await;

        for peer_msg in peer_iter {
            tokio::time::sleep(Duration::from_millis(100)).await;

            // for shares from peers we validate it, so we need to set the time provider to the share timestamp
            let mut time_provider = TestTimeProvider(SystemTime::now());
            if let Message::ShareBlock(share) = &peer_msg {
                time_provider.set_time(share.header.miner_share.ntime);
            }

            tokio::time::sleep(Duration::from_millis(100)).await;

            let response = handle_request_with_service(
                peer_id,
                peer_msg.clone(),
                chain_handle.clone(),
                response_channel_tx.clone(),
                swarm_tx.clone(),
                &time_provider,
            )
            .await;
            let _ww = chain_handle.get_workbase(7473434392883363844).await;
            tracing::debug!("Peer message response: {:?}", &response);
            assert!(response.is_ok(), "Peer message handling failed");
        }

        tokio::time::sleep(Duration::from_millis(500)).await;

        let peer_shares = chain_handle.get_shares_at_height(0).await;
        let peer_share = peer_shares.values().next().unwrap();

        // For this test, we forced prev_share_blockhash to be None
        assert!(
            peer_share.header.prev_share_blockhash.is_none(),
            "Previous share blockhash mismatch",
        );

        let ckpool_workbase = chain_handle
            .get_workbase(7473434392883363843)
            .await
            .unwrap();
        assert_eq!(
            ckpool_workbase.gbt.height, 123,
            "CKPool workbase height mismatch"
        );

        let peer_workbase = chain_handle
            .get_workbase(7473434392883363844)
            .await
            .unwrap();
        assert_eq!(
            peer_workbase.gbt.height, 123,
            "Peer workbase height mismatch"
        );

        node_handle
            .shutdown()
            .await
            .expect("Failed to shutdown node");
    }

    #[tokio::test]
    async fn test_rate_limiting() {
        let mut config = default_test_config()
            .with_listen_address("/ip4/127.0.0.1/tcp/6894".to_string())
            .with_store_path("test_rate_limit.db".to_string())
            .with_miner_pubkey(
                "020202020202020202020202020202020202020202020202020202020202020202".to_string(),
            );

        // setting low rate limits for testing.
        config.network.max_workbase_per_second = 1;
        config.network.max_userworkbase_per_second = 1;
        config.network.rate_limit_window_secs = 1;

        let temp_dir = tempdir().unwrap();
        let chain_handle = ChainHandle::new(
            temp_dir.path().to_str().unwrap().to_string(),
            ShareBlock::build_genesis_for_network(config.bitcoin.network),
        );

        let (node_handle, _stop_rx) = NodeHandle::new(config.clone(), chain_handle.clone())
            .await
            .expect("Failed to create node");

        let peer_id = libp2p::PeerId::random();
        let (swarm_tx, mut _swarm_rx) = mpsc::channel(100);
        let workbase = simple_miner_workbase();
        let time_provider = SystemTimeProvider {};

        // sending two workbase messages quickly, the second one should be rate-limited.
        let result1 = handle_request_with_service(
            peer_id,
            Message::Workbase(workbase.clone()),
            chain_handle.clone(),
            (),
            swarm_tx.clone(),
            &time_provider,
        )
        .await;

        let result2 = handle_request_with_service(
            peer_id,
            Message::Workbase(workbase.clone()),
            chain_handle.clone(),
            (),
            swarm_tx.clone(),
            &time_provider,
        )
        .await;

        assert!(result1.is_ok(), "First request should succeed");
        assert!(result2.is_ok(), "Second request should be rate limited");

        // wait longer than the rate limit window, then send again to succed
        tokio::time::sleep(Duration::from_secs(2)).await;
        let result3 = handle_request_with_service(
            peer_id,
            Message::Workbase(workbase.clone()),
            chain_handle.clone(),
            (),
            swarm_tx.clone(),
            &time_provider,
        )
        .await;
        assert!(
            result3.is_ok(),
            "Third request should succeed after waiting"
        );

        node_handle
            .shutdown()
            .await
            .expect("Failed to shutdown node");
    }
}
