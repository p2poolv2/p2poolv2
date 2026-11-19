// SPDX-FileCopyrightText: 2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Integration tests for reading a wallet's chain identity from the real
//! Electrum server, running on a confirmed test share chain.

use bitcoin::Network;
use p2poolv2_electrum::test_utils::start_test_server;
use p2poolv2_lib::test_utils::{build_confirmed_test_chain, setup_test_chain_store_handle};
use p2poolv2_wallet::ChainIdentity;
use p2poolv2_wallet::electrum::{ElectrumError, fetch_chain_identity};
use tokio::task::spawn_blocking;
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn chain_identity_is_read_from_the_server_and_its_network_checked() {
    //* Serve a test share chain, genesis plus one confirmed share, from the real Electrum server.
    let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
    let blocks = build_confirmed_test_chain(&chain_store_handle, 1).await;
    let shutdown = CancellationToken::new();
    let (address, _server) = start_test_server(chain_store_handle, shutdown.clone()).await;
    let url = format!("tcp://{address}");

    //* Reading the identity for signet, the server's network, returns signet and the genesis share's hash.
    let signet_url = url.clone();
    let identity = spawn_blocking(move || fetch_chain_identity(&signet_url, Network::Signet))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        identity,
        ChainIdentity {
            network: Network::Signet,
            sharechain_genesis_hash: blocks[0].block_hash(),
        }
    );

    //* Reading it for testnet4 is refused with the server's actual network, then the server stops.
    let mismatch = spawn_blocking(move || fetch_chain_identity(&url, Network::Testnet4))
        .await
        .unwrap();
    assert!(matches!(
        mismatch,
        Err(ElectrumError::NetworkMismatch {
            expected: Network::Testnet4,
            actual: Network::Signet,
        })
    ));
    shutdown.cancel();
}
