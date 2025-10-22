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

use crate::stratum::work::block_template::BlockTemplate;
use crate::stratum::work::error::WorkError;
use crate::stratum::work::notify::NotifyCmd;
use bitcoin::hashes::{Hash, sha256d};
use bitcoindrpc::{BitcoinRpcConfig, BitcoindRpcClient};
use std::sync::Arc;
use tracing::{debug, info};

/// Compute merkle branches for the transactions in the block template
/// Uses private compute_merkle_branches after parsing the txids from the template
#[allow(dead_code)]
pub fn build_merkle_branches_for_template(template: &BlockTemplate) -> Vec<sha256d::Hash> {
    let txids = template
        .transactions
        .iter()
        .map(|tx| tx.txid.parse().unwrap())
        .collect();
    compute_merkle_branches(txids)
}

/// Compute merkle branch from coinbase transaction and BlockTemplate's transactions
#[allow(dead_code)]
fn compute_merkle_branches(input_txids: Vec<sha256d::Hash>) -> Vec<sha256d::Hash> {
    let mut txids = input_txids.clone();
    let mut merkle_branches = Vec::new();
    while !txids.is_empty() {
        merkle_branches.push(txids[0]);
        let mut new_txids = Vec::new();
        for i in (1..txids.len()).step_by(2) {
            let left = txids[i];
            let right = if i + 1 < txids.len() {
                txids[i + 1]
            } else {
                left
            };
            let hash = sha256d::Hash::hash(&[left, right].concat());
            new_txids.push(hash);
        }
        txids = new_txids;
    }
    merkle_branches
}

/// Get a new blocktemplate from the bitcoind server
/// Parse the received JSON into a BlockTemplate struct and return it.
#[allow(dead_code)]
async fn get_block_template(
    bitcoin_config: &BitcoinRpcConfig,
    network: bitcoin::Network,
) -> Result<BlockTemplate, Box<dyn std::error::Error + Send + Sync>> {
    let bitcoind: BitcoindRpcClient = match BitcoindRpcClient::new(
        &bitcoin_config.url,
        &bitcoin_config.username,
        &bitcoin_config.password,
    ) {
        Ok(bitcoind) => bitcoind,
        Err(e) => {
            info!("Failed to connect to bitcoind: {}", e);
            return Err(Box::new(WorkError {
                message: format!("Failed to connect to bitcoind: {e}"),
            }));
        }
    };

    match bitcoind.getblocktemplate(network).await {
        Ok(blocktemplate_json) => {
            match serde_json::from_str::<BlockTemplate>(blocktemplate_json.as_str()) {
                Ok(template) => Ok(template),
                Err(e) => Err(Box::new(WorkError {
                    message: format!("Failed to parse block template: {e}"),
                })),
            }
        }
        Err(e) => Err(Box::new(WorkError {
            message: format!("Failed to get block template: {e}"),
        })),
    }
}

/// Print the current network difficulty
/// Called from start_gbt when it is first invoked
async fn print_start_network_diff(bitcoin_config: &BitcoinRpcConfig) {
    let bitcoind = BitcoindRpcClient::new(
        &bitcoin_config.url,
        &bitcoin_config.username,
        &bitcoin_config.password,
    )
    .unwrap();
    let difficulty = bitcoind.get_difficulty().await.unwrap();
    info!("Bitcoin network difficulty: {}", difficulty);
}

/// Start a task to fetch block templates from bitcoind
///
/// Listen to zmqpubhashblock from bitcoind.
/// Otherwise, poll for new block templates every poll_interval seconds.
pub async fn start_gbt(
    bitcoin_config: BitcoinRpcConfig,
    result_tx: tokio::sync::mpsc::Sender<NotifyCmd>,
    poll_interval: u64,
    network: bitcoin::Network,
    mut zmq_trigger_rx: tokio::sync::mpsc::Receiver<()>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    print_start_network_diff(&bitcoin_config).await;

    let template = match get_block_template(&bitcoin_config, network).await {
        Ok(template) => template,
        Err(e) => {
            info!("Error getting block template: {}", e);
            return Err(Box::new(WorkError {
                message: format!("Error getting initial block template: {e}"),
            }));
        }
    };

    // Initial template sent to start gbt task.
    if result_tx
        .send(NotifyCmd::SendToAll {
            template: Arc::new(template),
        })
        .await
        .is_err()
    {
        info!("Failed to send block template to channel");
    }

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(poll_interval));

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    match get_block_template(&bitcoin_config, network).await {
                        Ok(template) => {
                            if result_tx.send(NotifyCmd::SendToAll { template: Arc::new(template) }).await.is_err() {
                                info!("Failed to send block template to channel");
                            }
                        }
                        Err(e) => {
                            info!("Error polling block template: {}", e);
                        }
                    }
                }
                result = zmq_trigger_rx.recv() => {
                    match result {
                        Some(_) => {
                            debug!("Received ZMQ block notification");
                            match get_block_template(&bitcoin_config, network).await {
                                Ok(template) => {
                                    if result_tx.send(NotifyCmd::SendToAll { template: Arc::new(template) }).await.is_err() {
                                        info!("Failed to send block template to channel");
                                    }
                                    interval.reset();
                                }
                                Err(e) => {
                                    info!("Error getting block template after ZMQ notification: {}", e);
                                }
                            }
                        }
                        None => {
                            info!("ZMQ channel closed, stopping GBT task");
                            break;
                        }
                    }
                }
            }
        }
    });
    Ok(())
}

#[cfg(test)]
mod gbt_load_tests {
    use super::*;
    use bitcoin::hex::FromHex;
    use bitcoindrpc::test_utils::{mock_method, setup_mock_bitcoin_rpc};

    #[tokio::test]
    async fn test_get_block_template() {
        let template = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../tests/test_data/gbt/signet/gbt-no-transactions.json"),
        )
        .expect("Failed to read test fixture");

        let (mock_server, bitcoinrpc_config) = setup_mock_bitcoin_rpc().await;
        let params = serde_json::json!([{
            "capabilities": ["coinbasetxn", "coinbase/append", "workid"],
            "rules": ["segwit", "signet"],
        }]);
        mock_method(&mock_server, "getblocktemplate", params, template).await;

        let result = get_block_template(&bitcoinrpc_config, bitcoin::Network::Signet).await;

        assert!(result.is_ok());
        let template = result.unwrap();
        assert_eq!(template.version, 536870912);
        assert_eq!(template.rules.len(), 4);
        assert_eq!(template.rules[1], "!segwit");
        assert_eq!(
            template.previousblockhash,
            "000000006648c58af2ea07d976804c4cbd40377e566af5694f14ecac2b0065c1"
        );
        assert_eq!(
            template.default_witness_commitment,
            Some(
                "6a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf9"
                    .to_string()
            )
        )
    }

    // The test data comes from tests/test_data/gbt/regtest/ckpool/one-txn dir
    #[test_log::test]
    fn test_compute_merkle_branches_single_txid() {
        // Only one txid, branch should be just that txid
        let txid: sha256d::Hash =
            "2305d23e3d6a9f55189723e0dfc653908455a9162b263a0b7b584711cff8cdfe"
                .parse()
                .unwrap();
        let branches = compute_merkle_branches(vec![txid]);
        assert_eq!(branches, vec![txid]);
    }

    // The test data comes from tests/test_data/gbt/regtest/ckpool/two-txns dir
    #[test]
    fn test_compute_merkle_branches_two_txids() {
        let txid1: sha256d::Hash =
            "9a1644beab4dfaccc9bb3cbd5008b0581dd314102fcd79b69a2c724a8010d706"
                .parse()
                .unwrap();
        let txid2: sha256d::Hash =
            "3bca24fa1c1bc8cfcf77dfd974bb5c80ea865caa828c2e43f86cea862d5d6e40"
                .parse()
                .unwrap();

        let expected_hash = sha256d::Hash::hash(&[txid2, txid2].concat());
        let branches = compute_merkle_branches(vec![txid1, txid2]);
        assert_eq!(branches.len(), 2);
        assert_eq!(branches[0], txid1);
        assert_eq!(branches[1], expected_hash);

        // The expected merkle branches from ckpool's notify messages
        let v1 = Vec::from_hex("06d710804a722c9ab679cd2f1014d31d58b00850bd3cbbc9ccfa4dabbe44169a")
            .unwrap();
        let v2 = Vec::from_hex("dfa3f22130ce2941d79b5f6c35d15f15688910e49b4d7e460f07cb44c925ca49")
            .unwrap();
        let expected: Vec<sha256d::Hash> = vec![
            sha256d::Hash::from_slice(&v1).unwrap(),
            sha256d::Hash::from_slice(&v2).unwrap(),
        ];
        assert_eq!(branches, expected);
    }

    // The test data comes from tests/test_data/gbt/regtest/ckpool/three-txns dir
    #[test]
    fn test_compute_merkle_branches_three_txids() {
        let txid1: sha256d::Hash =
            "4193df037a4d8ffb9815f2fdae19abab69821f06625004a1e84d8df73cc0c044"
                .parse()
                .unwrap();
        let txid2: sha256d::Hash =
            "082af095391dbb4d8918765f41524e010ee3838adf3b3b13f280a6c83cad7776"
                .parse()
                .unwrap();
        let txid3: sha256d::Hash =
            "58dd52c691e92e6e9da0be3146dfdc87c2c7c1ab6e64476f26427c6d771de6a5"
                .parse()
                .unwrap();

        let h23 = sha256d::Hash::hash(&[txid2, txid3].concat());
        let branches = compute_merkle_branches(vec![txid1, txid2, txid3]);

        assert_eq!(branches[0], txid1);
        assert_eq!(branches[1], h23);
        assert_eq!(branches.len(), 2);

        // The expected merkle branches from ckpool's notify messages
        let v1 = Vec::from_hex("44c0c03cf78d4de8a1045062061f8269abab19aefdf21598fb8f4d7a03df9341")
            .unwrap();
        let v2 = Vec::from_hex("0dce56f68943df6531358e75bcad1e49e2456413cfd03244beaabc8cc9b69ee3")
            .unwrap();
        let expected: Vec<sha256d::Hash> = vec![
            sha256d::Hash::from_slice(&v1).unwrap(),
            sha256d::Hash::from_slice(&v2).unwrap(),
        ];
        assert_eq!(branches, expected);
    }

    // The test data comes from tests/test_data/gbt/regtest/ckpool/three-txns dir
    #[test]
    fn test_compute_merkle_branches_four_txids() {
        let txid1: sha256d::Hash =
            "19d9fe2c24a7b88b4d0455c9f42ce16eec881a9fc2cf1194a554129f8e297c27"
                .parse()
                .unwrap();
        let txid2: sha256d::Hash =
            "c3e8a4a3405cafc0ac48a1c602cf6962c74f180dccbd7a423a9216497dcb474e"
                .parse()
                .unwrap();
        let txid3: sha256d::Hash =
            "1b991d93da9c481637d7285ec378d4b1fd6b1ccb06fed594951f3705b3869ddb"
                .parse()
                .unwrap();
        let txid4: sha256d::Hash =
            "13a0ba57fdd05ce8b89950f792d8849ee636831a77d9f1eb1fda38e68991a2f0"
                .parse()
                .unwrap();

        let h23 = sha256d::Hash::hash(&[txid2, txid3].concat());
        let h44 = sha256d::Hash::hash(&[txid4, txid4].concat());
        let h4444 = sha256d::Hash::hash(&[h44, h44].concat());

        let branches = compute_merkle_branches(vec![txid1, txid2, txid3, txid4]);
        assert_eq!(branches[0], txid1);
        assert_eq!(branches[1], h23);
        assert_eq!(branches[2], h4444);
        assert_eq!(branches.len(), 3);

        // The expected merkle branches from ckpool's notify messages
        let v1 = Vec::from_hex("277c298e9f1254a59411cfc29f1a88ec6ee12cf4c955044d8bb8a7242cfed919")
            .unwrap();
        let v2 = Vec::from_hex("20838512651774fd1482b92f7d55e14103e773b92721873a29bb06846f297683")
            .unwrap();
        let v3 = Vec::from_hex("50c833466187becdc8e2f069352e7be34da07d653793093861c913eef295285c")
            .unwrap();
        let expected: Vec<sha256d::Hash> = vec![
            sha256d::Hash::from_slice(&v1).unwrap(),
            sha256d::Hash::from_slice(&v2).unwrap(),
            sha256d::Hash::from_slice(&v3).unwrap(),
        ];
        assert_eq!(branches, expected);
    }
}

#[cfg(test)]
mod gbt_server_tests {
    use super::*;
    use bitcoindrpc::test_utils::{mock_method, setup_mock_bitcoin_rpc};
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_start_gbt_trigger_from_timeout() {
        let binding = tempfile::tempdir().unwrap();
        let binding = binding.path().join("notify.sock");

        // Mock bitcoind RPC
        let template = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../tests/test_data/gbt/signet/gbt-no-transactions.json"),
        )
        .expect("Failed to read test fixture");

        let (mock_server, bitcoinrpc_config) = setup_mock_bitcoin_rpc().await;
        let params = serde_json::json!([{
            "capabilities": ["coinbasetxn", "coinbase/append", "workid"],
            "rules": ["segwit", "signet"],
        }]);
        mock_method(&mock_server, "getblocktemplate", params, template).await;
        mock_method(
            &mock_server,
            "getdifficulty",
            serde_json::json!([]),
            "1".into(),
        )
        .await;

        let (_zmq_trigger_tx, zmq_trigger_rx) = mpsc::channel(1);

        // Setup channel for receiving templates
        let (template_tx, mut template_rx) = mpsc::channel(10);

        // Start GBT server
        let result = start_gbt(
            bitcoinrpc_config,
            template_tx,
            1,
            bitcoin::Network::Signet,
            zmq_trigger_rx,
        )
        .await;

        assert!(result.is_ok());

        // We should receive a template after a second, but we wait for 2 seconds to ensure it is received
        let timeout =
            tokio::time::timeout(std::time::Duration::from_secs(2), template_rx.recv()).await;

        assert!(timeout.is_ok());
        let cmd = timeout.unwrap().unwrap();
        match cmd {
            NotifyCmd::SendToAll { template } => {
                assert_eq!(template.height, 108);
            }
            _ => panic!("Expected NotifyCmd::SendToAll"),
        }
    }

    #[tokio::test]
    async fn test_start_gbt_trigger_from_zmq_event() {
        let binding = tempfile::tempdir().unwrap();
        let binding = binding.path().join("notify.sock");

        // Mock bitcoind RPC
        let template = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../tests/test_data/gbt/signet/gbt-no-transactions.json"),
        )
        .expect("Failed to read test fixture");

        let (mock_server, bitcoinrpc_config) = setup_mock_bitcoin_rpc().await;
        let params = serde_json::json!([{
            "capabilities": ["coinbasetxn", "coinbase/append", "workid"],
            "rules": ["segwit", "signet"],
        }]);
        mock_method(&mock_server, "getblocktemplate", params, template).await;
        mock_method(
            &mock_server,
            "getdifficulty",
            serde_json::json!([]),
            "1".into(),
        )
        .await;

        let (zmq_trigger_tx, zmq_trigger_rx) = mpsc::channel(1);

        // Setup channel for receiving templates
        let (template_tx, mut template_rx) = mpsc::channel(10);

        // Start GBT server
        let result = start_gbt(
            bitcoinrpc_config,
            template_tx,
            60,
            bitcoin::Network::Signet,
            zmq_trigger_rx,
        )
        .await;

        println!("Result: {:?}", result);

        assert!(result.is_ok());

        // send message from ZMQ server
        zmq_trigger_tx.send(()).await.unwrap();

        // We should receive a template
        let timeout =
            tokio::time::timeout(std::time::Duration::from_secs(1), template_rx.recv()).await;

        assert!(timeout.is_ok());
        let cmd = timeout.unwrap().unwrap();
        match cmd {
            NotifyCmd::SendToAll { template } => {
                assert_eq!(template.height, 108);
            }
            _ => panic!("Expected NotifyCmd::SendToAll"),
        }
    }
}
