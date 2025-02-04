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

mod self_and_peer_messages_tests {
    use super::common::default_test_config;
    use p2poolv2::node::actor::NodeHandle;
    use p2poolv2::node::messages::Message;
    use p2poolv2::node::request_response_handler::handle_request;
    use p2poolv2::shares::chain::ChainHandle;
    use p2poolv2::shares::miner_message::CkPoolMessage;
    use p2poolv2::shares::ShareBlock;
    use std::fs;
    use std::time::Duration;
    use tempfile;
    use tempfile::tempdir;
    use tokio::sync::mpsc;
    use zmq;

    #[tokio::test]
    async fn receive_shares_and_workbases_from_self_and_peers() {
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
                    let mut peer_share = ShareBlock::new(share, pubkey, bitcoin::Network::Regtest);
                    // set all peer shares to have the same prev_share_blockhash
                    peer_share.prev_share_blockhash = Some(
                        "00000000debd331503c0e5348801a2057d2b8c8b96dcfb075d5a283954846172"
                            .parse()
                            .unwrap(),
                    );
                    Message::ShareBlock(peer_share)
                }
                CkPoolMessage::Workbase(workbase) => Message::Workbase(workbase),
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

        let mut ckpool_iter = ckpool_messages.iter();
        let mut peer_iter = peer_messages.iter();
        let peer_id = libp2p::PeerId::random();
        let (swarm_tx, mut swarm_rx) = mpsc::channel(100);
        tokio::spawn(async move {
            while let Some(_) = swarm_rx.recv().await {
                tracing::debug!("Received swarm send");
            }
        });

        while let (Some(ckpool_msg), Some(peer_msg)) = (ckpool_iter.next(), peer_iter.next()) {
            let serialized = serde_json::to_string(&ckpool_msg).unwrap();
            tracing::debug!("Publishing CKPool message: {:?}", &ckpool_msg);
            publisher
                .send(&serialized, 0)
                .expect("Failed to publish message");

            tokio::time::sleep(Duration::from_millis(100)).await;

            tracing::debug!("Sending peer message: {:?}", &peer_msg);
            let response = handle_request(
                peer_id,
                peer_msg.clone(),
                chain_handle.clone(),
                swarm_tx.clone(),
            )
            .await;
            tracing::debug!("Peer message response: {:?}", &response);
            assert!(response.is_ok(), "Peer message handling failed");

            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        for msg in ckpool_iter {
            let serialized = serde_json::to_string(&msg).unwrap();
            publisher
                .send(&serialized, 0)
                .expect("Failed to publish message");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        for msg in peer_iter {
            let response =
                handle_request(peer_id, msg.clone(), chain_handle.clone(), swarm_tx.clone()).await;
            assert!(response.is_ok(), "Peer message handling failed");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        tokio::time::sleep(Duration::from_millis(500)).await;

        assert!(
            chain_handle
                .get_share(
                    "00000000debd331503c0e5348801a2057d2b8c8b96dcfb075d5a283954846172"
                        .parse()
                        .unwrap()
                )
                .await
                .is_some(),
            "CKPool share not found"
        );

        assert!(
            chain_handle
                .get_share(
                    "00000000debd331503c0e5348801a2057d2b8c8b96dcfb075d5a283954846173"
                        .parse()
                        .unwrap()
                )
                .await
                .is_some(),
            "Peer share not found"
        );

        let peer_share = chain_handle
            .get_share(
                "00000000debd331503c0e5348801a2057d2b8c8b96dcfb075d5a283954846173"
                    .parse()
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            peer_share.prev_share_blockhash,
            Some(
                "00000000debd331503c0e5348801a2057d2b8c8b96dcfb075d5a283954846172"
                    .parse()
                    .unwrap()
            ),
            "Previous share blockhash mismatch"
        );

        let ckpool_workbase = chain_handle
            .get_workbase(7460801854683742211)
            .await
            .unwrap();
        assert_eq!(
            ckpool_workbase.gbt.height, 109,
            "CKPool workbase height mismatch"
        );

        let peer_workbase = chain_handle
            .get_workbase(7460801854683742212)
            .await
            .unwrap();
        assert_eq!(
            peer_workbase.gbt.height, 109,
            "Peer workbase height mismatch"
        );

        node_handle
            .shutdown()
            .await
            .expect("Failed to shutdown node");
    }
}
