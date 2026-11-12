// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Create a miner address from an existing bitcoind wallet.
//!
//! Talks to bitcoind over RPC using the `[bitcoinrpc]` config. The wallet
//! must already exist in bitcoind: it is already loaded, or loaded from disk,
//! never created. Derives one bech32m (P2TR) address from it and re-encodes
//! its `witness_program` as a share chain address.
//!
//! The private key never leaves bitcoind. No P2Poolv2 crate generates or
//! handles private keys. See `docs/architecture/address-format.md`.

use crate::commands::address;
use bitcoin::Network;
use bitcoindrpc::{BitcoinRpcConfig, BitcoindRpcClient, BitcoindRpcError};
use p2poolv2_lib::config::Config;
use p2poolv2_wallet::Address;
use std::error::Error;

/// Execute the new-address command for a loaded config.
pub async fn execute(
    config: &Config,
    network: Option<Network>,
    wallet_name: &str,
) -> Result<(), Box<dyn Error>> {
    let network = network.unwrap_or_else(|| config.stratum.network());
    let client = wallet_client(&config.bitcoinrpc, wallet_name).await?;
    let (bitcoin_address, share_address, output_key_hex) =
        derive_addresses(&client, network).await?;

    println!("Bitcoin Address: {bitcoin_address}");
    println!("ShareChain Address: {share_address}");
    println!("Taproot Output Key (hex): {output_key_hex}");
    Ok(())
}

/// Derive one new taproot address from the wallet and re-encode its output
/// key as a share chain address. Returns the bitcoin address, the share
/// chain address and the hex output key, in print order.
async fn derive_addresses(
    client: &BitcoindRpcClient,
    network: Network,
) -> Result<(String, Address, String), Box<dyn Error>> {
    let bitcoin_address = client.getnewaddress("p2poolv2", "bech32m").await?;
    let info = client.getaddressinfo(&bitcoin_address).await?;
    let output_key_hex = info.witness_program.ok_or_else(|| {
        format!("getaddressinfo for {bitcoin_address} returned no witness program; expected a bech32m (taproot) address")
    })?;
    let share_address = address::encode(&output_key_hex, network)?;
    Ok((bitcoin_address, share_address, output_key_hex))
}

/// Build an RPC client. An empty wallet path talks to the node's default
/// wallet-less endpoint; a wallet path scopes requests to that wallet.
fn rpc_client(
    rpc: &BitcoinRpcConfig,
    wallet_path: &str,
) -> Result<BitcoindRpcClient, BitcoindRpcError> {
    let url = if wallet_path.is_empty() {
        rpc.url.trim_end_matches('/').to_string()
    } else {
        format!("{}/wallet/{}", rpc.url.trim_end_matches('/'), wallet_path)
    };
    BitcoindRpcClient::new(&url, &rpc.username, &rpc.password)
}

/// Return a client scoped to `wallet_name`, which must already exist in
/// bitcoind: either loaded or loadable from disk. Creating wallets is left
/// to the operator, for example with `bitcoin-cli createwallet <name>`.
async fn wallet_client(
    rpc: &BitcoinRpcConfig,
    wallet_name: &str,
) -> Result<BitcoindRpcClient, Box<dyn Error>> {
    // Check node liveness first, so an unreachable node or bad credentials
    // is reported as such instead of as a missing wallet.
    rpc_client(rpc, "")?.getblockchaininfo().await?;

    let client = rpc_client(rpc, wallet_name)?;
    let probe_error = match client.getwalletinfo().await {
        Ok(()) => return Ok(client),
        Err(error) => error,
    };
    // Only a wallet that is missing or not loaded is worth a loadwallet
    // attempt; anything else is a different failure and must surface as is.
    if !wallet_not_loaded(&probe_error) {
        return Err(probe_error.into());
    }

    rpc_client(rpc, "")?
        .loadwallet(wallet_name)
        .await
        .map_err(|error| {
            Box::<dyn Error>::from(format!(
                "wallet '{wallet_name}' is not loaded in bitcoind. Load it or create it first, for example with `bitcoin-cli createwallet {wallet_name}`: {error}"
            ))
        })?;
    Ok(client)
}

/// True when the error text says the wallet is missing or not loaded.
///
/// Bitcoin Core answers some RPC errors over HTTP 200 and others over
/// HTTP 500 with the JSON body, so both error variants must be inspected.
fn wallet_not_loaded(error: &BitcoindRpcError) -> bool {
    let message = match error {
        BitcoindRpcError::RpcError { message, .. } => message,
        BitcoindRpcError::HttpError { message, .. } => message,
        _ => return false,
    };
    message.contains("does not exist or is not loaded")
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoindrpc::test_utils::{respond, respond_error, setup_mock_bitcoin_rpc};
    use wiremock::Mock;
    use wiremock::matchers::{body_partial_json, method, path};

    /// The worked example in docs/architecture/address-format.md: the witness
    /// program of tb1p504yc8zlqs4w077ss6787v8z5zxgke6nc333md75k87t82u5ryqq0gh57d.
    const WALLET_OUTPUT_KEY: &str =
        "a3ea4c1c5f042ae7fbd086bc7f30e2a08c8b6753c4631db7d4b1fcb3ab941900";

    #[tokio::test]
    async fn loads_existing_wallet() {
        let (server, config) = setup_mock_bitcoin_rpc().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_partial_json(serde_json::json!({
                "method": "getblockchaininfo",
            })))
            .respond_with(respond(serde_json::json!({
                "initialblockdownload": false,
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/wallet/miner"))
            .and(body_partial_json(serde_json::json!({
                "method": "getwalletinfo",
            })))
            .respond_with(respond_error(
                -18,
                "Requested wallet does not exist or is not loaded",
            ))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_partial_json(serde_json::json!({
                "method": "loadwallet",
                "params": ["miner"],
            })))
            .respond_with(respond(serde_json::json!({ "name": "miner" })))
            .mount(&server)
            .await;

        wallet_client(&config, "miner")
            .await
            .expect("wallet loaded");
    }

    #[tokio::test]
    async fn points_at_createwallet_when_wallet_is_missing() {
        let (server, config) = setup_mock_bitcoin_rpc().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_partial_json(serde_json::json!({
                "method": "getblockchaininfo",
            })))
            .respond_with(respond(serde_json::json!({
                "initialblockdownload": false,
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/wallet/miner"))
            .and(body_partial_json(serde_json::json!({
                "method": "getwalletinfo",
            })))
            .respond_with(respond_error(
                -18,
                "Requested wallet does not exist or is not loaded",
            ))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_partial_json(serde_json::json!({
                "method": "loadwallet",
            })))
            .respond_with(respond_error(
                -18,
                "Requested wallet does not exist or is not loaded",
            ))
            .mount(&server)
            .await;

        let error = wallet_client(&config, "miner")
            .await
            .expect_err("missing wallet");
        assert!(
            error.to_string().contains("bitcoin-cli createwallet miner"),
            "unexpected error: {error}"
        );
    }

    #[tokio::test]
    async fn reports_node_liveness_failure_instead_of_missing_wallet() {
        let (server, config) = setup_mock_bitcoin_rpc().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_partial_json(serde_json::json!({
                "method": "getblockchaininfo",
            })))
            .respond_with(respond_error(-28, "bitcoind is warming up"))
            .mount(&server)
            .await;

        let error = wallet_client(&config, "miner")
            .await
            .expect_err("node down");
        let error = error.to_string();
        assert!(error.contains("warming up"), "unexpected error: {error}");
        assert!(
            !error.contains("createwallet"),
            "liveness failure must not be reported as a missing wallet: {error}"
        );
    }

    #[tokio::test]
    async fn returns_the_loaded_wallet_without_loadwallet() {
        let (server, config) = setup_mock_bitcoin_rpc().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_partial_json(serde_json::json!({
                "method": "getblockchaininfo",
            })))
            .respond_with(respond(serde_json::json!({
                "initialblockdownload": false,
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/wallet/miner"))
            .and(body_partial_json(serde_json::json!({
                "method": "getwalletinfo",
            })))
            .respond_with(respond(serde_json::json!({
                "walletname": "miner",
            })))
            .mount(&server)
            .await;

        wallet_client(&config, "miner")
            .await
            .expect("wallet already loaded");
    }

    #[tokio::test]
    async fn derives_share_address_from_a_loaded_wallet() {
        let (server, config) = setup_mock_bitcoin_rpc().await;

        Mock::given(method("POST"))
            .and(path("/wallet/miner"))
            .and(body_partial_json(serde_json::json!({
                "method": "getnewaddress",
            })))
            .respond_with(respond(serde_json::json!(
                "tb1p504yc8zlqs4w077ss6787v8z5zxgke6nc333md75k87t82u5ryqq0gh57d"
            )))
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/wallet/miner"))
            .and(body_partial_json(serde_json::json!({
                "method": "getaddressinfo",
            })))
            .respond_with(respond(serde_json::json!({
                "witness_program": WALLET_OUTPUT_KEY,
            })))
            .mount(&server)
            .await;

        let client = rpc_client(&config, "miner").expect("client");
        let (bitcoin_address, share_address, output_key_hex) =
            derive_addresses(&client, Network::Signet)
                .await
                .expect("derived");

        assert_eq!(
            bitcoin_address,
            "tb1p504yc8zlqs4w077ss6787v8z5zxgke6nc333md75k87t82u5ryqq0gh57d"
        );
        assert_eq!(
            share_address.to_string(),
            "sp2pool1p504yc8zlqs4w077ss6787v8z5zxgke6nc333md75k87t82u5ryqqd9033x"
        );
        assert_eq!(output_key_hex, WALLET_OUTPUT_KEY);
    }

    #[tokio::test]
    async fn rejects_a_getaddressinfo_response_without_witness_program() {
        let (server, config) = setup_mock_bitcoin_rpc().await;

        Mock::given(method("POST"))
            .and(path("/wallet/miner"))
            .and(body_partial_json(serde_json::json!({
                "method": "getnewaddress",
            })))
            .respond_with(respond(serde_json::json!(
                "bcrt1qnotaproot00000000000000000000000000000000000000000000000x"
            )))
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/wallet/miner"))
            .and(body_partial_json(serde_json::json!({
                "method": "getaddressinfo",
            })))
            .respond_with(respond(serde_json::json!({
                "address": "bcrt1qnotaproot00000000000000000000000000000000000000000000000x",
            })))
            .mount(&server)
            .await;

        let client = rpc_client(&config, "miner").expect("client");
        let error = derive_addresses(&client, Network::Regtest)
            .await
            .expect_err("no witness program");
        let error = error.to_string();
        assert!(
            error.contains("no witness program"),
            "unexpected error: {error}"
        );
    }
}
