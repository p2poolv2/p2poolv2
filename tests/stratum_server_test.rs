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

use bitcoindrpc::test_utils::{mock_method, setup_mock_bitcoin_rpc};
use p2poolv2_lib::accounting::stats::metrics;
use p2poolv2_lib::shares::chain::chain_store::ChainStore;
use p2poolv2_lib::shares::share_block::ShareBlock;
use p2poolv2_lib::store::Store;
use p2poolv2_lib::stratum::{
    self, client_connections,
    messages::{Response, SimpleRequest},
    server::StratumServerBuilder,
    work::{notify, tracker::start_tracker_actor},
};
use std::net::SocketAddr;
use std::str;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[tokio::test]
async fn test_stratum_server_subscribe() {
    let addr: SocketAddr = "127.0.0.1:9999".parse().expect("Invalid address");

    // Setup server - using Arc so we can access it for shutdown
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let connections_handle = client_connections::start_connections_handler().await;
    let (notify_tx, _notify_rx) = tokio::sync::mpsc::channel::<notify::NotifyCmd>(100);

    let template = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/test_data/gbt/signet/gbt-no-transactions.json"),
    )
    .expect("Failed to read test fixture");
    let (mock_server, bitcoinrpc_config) = setup_mock_bitcoin_rpc().await;
    let params = serde_json::json!([{
        "capabilities": ["coinbasetxn", "coinbase/append", "workid"],
        "rules": ["segwit", "signet"],
    }]);
    mock_method(&mock_server, "getblocktemplate", params, template).await;

    let (share_block_tx, _share_block_rx) = tokio::sync::mpsc::channel(10);
    let stats_dir = tempfile::tempdir().unwrap();
    let metrics_handle = metrics::start_metrics(stats_dir.path().to_str().unwrap().to_string())
        .await
        .unwrap();

    let temp_dir = tempdir().unwrap();
    let store = Arc::new(ChainStore::new(
        Arc::new(Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap()),
        ShareBlock::build_genesis_for_network(bitcoin::Network::Signet),
        bitcoin::Network::Signet,
    ));

    let mut server = StratumServerBuilder::default()
        .shutdown_rx(shutdown_rx)
        .connections_handle(connections_handle)
        .emissions_tx(share_block_tx)
        .hostname("127.0.0.1".to_string())
        .port(9999)
        .start_difficulty(1)
        .minimum_difficulty(1)
        .maximum_difficulty(Some(1))
        .zmqpubhashblock("tcp://127.0.0.1:28332".to_string())
        .network(bitcoin::network::Network::Regtest)
        .version_mask(0x1fffe000)
        .store(store)
        .build()
        .await
        .unwrap();

    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let tracker_handle = start_tracker_actor();

    tokio::spawn(async move {
        let _result = server
            .start(
                Some(ready_tx),
                notify_tx,
                tracker_handle,
                bitcoinrpc_config,
                metrics_handle,
            )
            .await;
    });
    ready_rx.await.expect("Server failed to start");

    let mut client = match TcpStream::connect(addr).await {
        Ok(stream) => stream,
        Err(e) => {
            panic!("Failed to connect to server: {e}");
        }
    };

    let subscribe_msg =
        SimpleRequest::new_subscribe(1, "agent".to_string(), "1.0".to_string(), None);
    let subscribe_str =
        serde_json::to_string(&subscribe_msg).expect("Failed to serialize subscribe message");
    client
        .write_all((subscribe_str + "\n").as_bytes())
        .await
        .expect("Failed to send subscribe message");

    let mut buffer = [0; 1024];
    let bytes_read = client
        .read(&mut buffer)
        .await
        .expect("Failed to read response");
    let response_str = str::from_utf8(&buffer[..bytes_read]).expect("Invalid UTF-8");

    let responses: Vec<&str> = response_str.split('\n').filter(|s| !s.is_empty()).collect();

    let response_message: Response =
        serde_json::from_str(responses[0]).expect("Failed to deserialize response as Response");

    assert_eq!(
        response_message.id,
        Some(stratum::messages::Id::Number(1)),
        "Response ID doesn't match request ID"
    );
    assert!(
        response_message.result.is_some(),
        "Response missing 'result' field"
    );
    assert!(
        response_message.error.is_none(),
        "Response should not contain 'error' field"
    );
    response_message.result.unwrap();

    drop(client);

    shutdown_tx
        .send(())
        .expect("Failed to send shutdown signal to server");
}
